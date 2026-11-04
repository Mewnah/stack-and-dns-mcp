/**
 * Round 8, platform group: configuration validation, the HTTP transport's
 * error shapes and limits, and the descriptions agents read (server
 * instructions, tool descriptions, output schema describes). Everything runs
 * on :memory: databases, in-memory MCP transports and 127.0.0.1 servers; no
 * test resolves a name or reaches the network.
 */

import assert from "node:assert/strict";
import { Resolver } from "node:dns/promises";
import type { Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { after, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StripeApi } from "../src/billing/stripeApi.js";
import { defaultX402AssetName, isResolverAddress, loadConfig, x402NetworkDefaults, type AppConfig } from "../src/config.js";
import { DnsClient } from "../src/lib/dns.js";
import { setLogLevel } from "../src/logger.js";
import { ApiKeyStore, SessionTokenService, type Principal } from "../src/middleware/auth.js";
import { PaymentManager } from "../src/middleware/payments.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { BillingSchema, EmailSnapshotSchema, JobItemSchema, StartBulkCheckInputSchema, startBulkCheckInputSchema, VerifyEmailInfrastructureOutputSchema } from "../src/schemas.js";
import { createMcpServer, serverInstructions } from "../src/server.js";
import { createServices, type Services } from "../src/services.js";
import { openStorage } from "../src/store/index.js";
import type { EmailScanInput } from "../src/store/scanStore.js";
import { EXPOSED_HEADERS, httpBodyLimits, rebindingProtection, startHttp, type SelfServeDeps } from "../src/transports/http.js";

setLogLevel("silent");

const ENTERPRISE_KEY = "sdm_live_round8_platform_enterprise_0001";
const LOCAL: Principal = { id: "local", plan: "local", label: "test", source: "local" };
const MIB = 1024 * 1024;

/** A DNS client that is never queried here; no resolver is configured beyond loopback and there is no fallback. */
function idleDns(): DnsClient {
  return new DnsClient({ servers: ["127.0.0.1"], fallbackServers: [] });
}

async function withServices(config: AppConfig): Promise<{ services: Services; usage: UsageTracker; limiter: RateLimiter; close: () => Promise<void> }> {
  const storage = await openStorage(config);
  assert.ok(storage, "an in-memory database opens");
  const usage = new UsageTracker(null);
  const limiter = new RateLimiter(config.auth.planLimits);
  const services = createServices({ config, dns: idleDns(), usage, limiter, storage });
  return {
    services,
    usage,
    limiter,
    close: async () => {
      await services.stop();
      await usage.close();
      storage.close();
    }
  };
}

async function mcpClient(config: AppConfig): Promise<{ client: Client; close: () => Promise<void> }> {
  const env = await withServices(config);
  const server = createMcpServer({ config, usage: env.usage, limiter: env.limiter, localPrincipal: LOCAL, dns: idleDns(), services: env.services });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "round8-platform", version: "1.0.0" });
  await client.connect(clientTransport);
  return {
    client,
    close: async () => {
      await client.close();
      await server.close();
      await env.close();
    }
  };
}

interface HttpHarness {
  base: string;
  close: () => Promise<void>;
}

async function httpHarness(env: Record<string, string> = {}, options: { selfServe?: boolean } = {}): Promise<HttpHarness> {
  const loaded = loadConfig({ STACKDNS_TRANSPORT: "http", STACKDNS_DB_FILE: ":memory:", STACKDNS_SESSION_SECRET: "round8-platform-session-secret", ...env }, []);
  const config: AppConfig = { ...loaded, http: { ...loaded.http, host: "127.0.0.1", port: 0 } };
  const services = await withServices(config);
  const keys = await ApiKeyStore.fromConfig(config);
  if (services.services.keys) keys.attachRepository(services.services.keys);
  const payments = new PaymentManager(config, services.usage);
  const selfServe: SelfServeDeps | null = options.selfServe
    ? {
        stripe: new StripeApi("sk_test_round8_platform", "http://127.0.0.1:9"),
        options: { publicUrl: config.http.publicUrl, prices: { pro: "price_round8" }, webhookSecret: null, planLimits: config.auth.planLimits }
      }
    : null;
  const server: HttpServer = await startHttp({
    config,
    usage: services.usage,
    limiter: services.limiter,
    localPrincipal: LOCAL,
    dns: idleDns(),
    services: services.services,
    keys,
    sessions: new SessionTokenService(config.auth.sessionSecret),
    payments,
    selfServe
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    base,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      payments.close();
      await services.close();
    }
  };
}

/** Captures what the logger writes to stderr while fn runs, at the given level. */
async function captureLogs<T>(level: "warn" | "info", fn: () => Promise<T>): Promise<{ value: T; lines: string[] }> {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  setLogLevel(level);
  // Swallowed rather than echoed, so the expected warning does not clutter the test output.
  process.stderr.write = ((chunk: string | Uint8Array) => {
    lines.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  try {
    return { value: await fn(), lines };
  } finally {
    process.stderr.write = original;
    setLogLevel("silent");
  }
}

describe("x402 asset domain (x402-asset-name-eip712-default)", () => {
  const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
  const SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
  const X402_ON = { STACKDNS_PAYMENTS_ENABLED: "true", STACKDNS_PAYMENT_METHODS: "x402" };

  it("defaults the EIP-712 name to the token's name() on the configured network and exposes the version", () => {
    const base = loadConfig({}, []).payments.x402;
    assert.equal(base.asset, BASE_USDC);
    assert.equal(base.assetName, "USD Coin", "native USDC on Base mainnet signs over the domain name USD Coin, not USDC");
    assert.equal(base.assetVersion, "2");
    assert.equal(loadConfig({ X402_NETWORK: "base-sepolia" }, []).payments.x402.assetName, "USDC", "the Base Sepolia test token is named USDC, so Sepolia setups keep working");
    assert.equal(defaultX402AssetName("eip155:84532"), "USDC");
    assert.equal(defaultX402AssetName("eip155:8453"), "USD Coin");
    const custom = loadConfig({ X402_ASSET_NAME: "Euro Coin", X402_ASSET_VERSION: "1" }, []).payments.x402;
    assert.equal(custom.assetName, "Euro Coin", "an explicit name always wins");
    assert.equal(custom.assetVersion, "1");
  });

  it("defaults the asset contract to the configured network's USDC (x402-sepolia-mainnet-asset)", () => {
    for (const network of ["base-sepolia", "eip155:84532", " Base-Sepolia "]) {
      const x = loadConfig({ X402_NETWORK: network, ...X402_ON }, []).payments.x402;
      assert.deepEqual({ asset: x.asset, name: x.assetName, version: x.assetVersion }, { asset: SEPOLIA_USDC, name: "USDC", version: "2" }, `${network} must not inherit the mainnet contract`);
      assert.equal(x.network, network === " Base-Sepolia " ? "base-sepolia" : network.trim(), `${network} is sent as the id the defaults were taken for`);
    }
    const mainnet = loadConfig({ X402_NETWORK: "eip155:8453", ...X402_ON }, []).payments.x402;
    assert.deepEqual({ asset: mainnet.asset, name: mainnet.assetName, version: mainnet.assetVersion }, { asset: BASE_USDC, name: "USD Coin", version: "2" });
    assert.deepEqual(x402NetworkDefaults("base-sepolia"), { asset: SEPOLIA_USDC, name: "USDC", version: "2" });
    assert.equal(x402NetworkDefaults("polygon"), null);
    const token = "0x1111111111111111111111111111111111111111";
    const explicit = loadConfig({ X402_NETWORK: "base", X402_ASSET: token, X402_ASSET_NAME: "Euro Coin", X402_ASSET_VERSION: "1", ...X402_ON }, []).payments.x402;
    assert.deepEqual({ asset: explicit.asset, name: explicit.assetName, version: explicit.assetVersion }, { asset: token, name: "Euro Coin", version: "1" }, "explicit values for another token win");
  });

  it("requires the asset and its name on a network without built-in defaults, only when x402 is on", () => {
    assert.doesNotThrow(() => loadConfig({ X402_NETWORK: "polygon" }, []), "unused x402 settings never fail startup");
    assert.throws(() => loadConfig({ X402_NETWORK: "polygon", ...X402_ON }, []), /X402_NETWORK "polygon" has no built-in asset defaults .*set X402_ASSET and X402_ASSET_NAME/);
    const token = "0x2222222222222222222222222222222222222222";
    assert.throws(() => loadConfig({ X402_NETWORK: "polygon", X402_ASSET: token, ...X402_ON }, []), /set X402_ASSET_NAME \(/);
    const set = loadConfig({ X402_NETWORK: "polygon", X402_ASSET: token, X402_ASSET_NAME: "USD Coin", ...X402_ON }, []).payments.x402;
    assert.deepEqual({ asset: set.asset, name: set.assetName, version: set.assetVersion }, { asset: token, name: "USD Coin", version: "2" });
  });

  it("refuses a built-in USDC contract named on the wrong network or under the wrong EIP-712 domain when x402 is on", () => {
    // A template that pins the mainnet contract, copied onto base-sepolia: every payment would fail on chain.
    assert.throws(
      () => loadConfig({ X402_NETWORK: "base-sepolia", X402_ASSET: BASE_USDC, ...X402_ON }, []),
      /X402_ASSET 0x8335.* is USDC on base, not on X402_NETWORK "base-sepolia"; leave X402_ASSET blank/
    );
    // The old .env.example pinned X402_ASSET_NAME=USDC next to mainnet USDC, whose name() is "USD Coin".
    assert.throws(
      () => loadConfig({ X402_ASSET: BASE_USDC, X402_ASSET_NAME: "USDC", ...X402_ON }, []),
      /X402_ASSET_NAME "USDC" .* do not match the EIP-712 domain of USDC on "base" \("USD Coin" \/ "2"\)/
    );
    assert.throws(() => loadConfig({ X402_NETWORK: "base-sepolia", X402_ASSET_VERSION: "1", ...X402_ON }, []), /X402_ASSET_VERSION "1"/);
    const pinned = loadConfig({ X402_ASSET: BASE_USDC.toLowerCase(), X402_ASSET_NAME: "USD Coin", X402_ASSET_VERSION: "2", ...X402_ON }, []).payments.x402;
    assert.equal(pinned.assetName, "USD Coin", "values that match the contract are accepted, whatever the address case");
    assert.doesNotThrow(() => loadConfig({ X402_NETWORK: "base-sepolia", X402_ASSET: BASE_USDC }, []), "with x402 off nothing is sent, so nothing is refused");
  });

  it("sends a recognised network in its canonical spelling and leaves any other id's case alone (r10-platform-x402-network-normalized-for-lookup-only)", async () => {
    // Clients and facilitators match the id exactly, so the Sepolia defaults under "Base-Sepolia" would fail every payment.
    const canonical: Array<[string, string]> = [
      ["Base", "base"],
      [" BASE ", "base"],
      ["EIP155:8453", "eip155:8453"],
      ["Base-Sepolia", "base-sepolia"],
      [" eip155:84532 ", "eip155:84532"]
    ];
    for (const [raw, sent] of canonical) {
      assert.equal(loadConfig({ X402_NETWORK: raw, ...X402_ON }, []).payments.x402.network, sent, raw);
      assert.equal(loadConfig({ X402_NETWORK: raw }, []).payments.x402.network, sent, `${raw} with x402 off`);
    }
    // CAIP-2 references such as a Solana genesis hash are case-sensitive: an id without defaults is only trimmed.
    const solana = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    const token = "0x3333333333333333333333333333333333333333";
    assert.equal(loadConfig({ X402_NETWORK: ` ${solana} `, X402_ASSET: token, X402_ASSET_NAME: "USD Coin", ...X402_ON }, []).payments.x402.network, solana);
    assert.equal(loadConfig({ X402_NETWORK: "Polygon" }, []).payments.x402.network, "Polygon");

    // The 402 challenge carries the id the asset was resolved for.
    const config = loadConfig({ X402_NETWORK: " Base-Sepolia ", X402_FACILITATOR_URL: "http://127.0.0.1:9/facilitator", X402_PAY_TO: "0x000000000000000000000000000000000000dEaD", ...X402_ON }, []);
    const usage = new UsageTracker(null);
    const payments = new PaymentManager(config, usage);
    try {
      const accepts = (await payments.createChallenge("http://127.0.0.1:1/mcp")).x402?.accepts;
      assert.deepEqual({ network: accepts?.network, asset: accepts?.asset, name: accepts?.extra.name }, { network: "base-sepolia", asset: SEPOLIA_USDC, name: "USDC" });
    } finally {
      payments.close();
      await usage.close();
    }
  });

  it("requires X402_ASSET_NAME for a token other than the built-in USDC on a network with defaults (r10-platform-x402-custom-asset-inherits-usdc-name)", () => {
    // EURC on Base: without a name it would sign over USDC's "USD Coin" domain, and every payment would fail verification.
    const eurc = "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42";
    assert.throws(
      () => loadConfig({ X402_NETWORK: "base", X402_ASSET: eurc, ...X402_ON }, []),
      /X402_ASSET 0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42 is not the built-in USDC for X402_NETWORK "base" \(0x8335.*\), so its EIP-712 domain is unknown; set X402_ASSET_NAME \(the token's EIP-712 name\(\)\)/
    );
    assert.throws(
      () => loadConfig({ X402_NETWORK: "eip155:84532", X402_ASSET: eurc, X402_ASSET_VERSION: "2", ...X402_ON }, []),
      /is not the built-in USDC for X402_NETWORK "eip155:84532".*set X402_ASSET_NAME/
    );
    const named = loadConfig({ X402_NETWORK: "base", X402_ASSET: eurc, X402_ASSET_NAME: "EURC", ...X402_ON }, []).payments.x402;
    // The version still defaults to 2, as on a network without defaults.
    assert.deepEqual({ asset: named.asset, name: named.assetName, version: named.assetVersion }, { asset: eurc, name: "EURC", version: "2" });
    assert.doesNotThrow(() => loadConfig({ X402_NETWORK: "base", X402_ASSET: eurc }, []), "with x402 off nothing is sent, so nothing is refused");
    assert.doesNotThrow(() => loadConfig({ X402_NETWORK: "base", X402_ASSET: BASE_USDC.toLowerCase(), ...X402_ON }, []), "built-in USDC needs no name");
  });
});

describe("payment methods (payment-methods-silent-fallback)", () => {
  it("normalizes case and refuses unknown methods instead of falling back to stripe", () => {
    assert.deepEqual(loadConfig({}, []).payments.methods, ["stripe"]);
    assert.deepEqual(loadConfig({ STACKDNS_PAYMENT_METHODS: "X402" }, []).payments.methods, ["x402"]);
    assert.deepEqual(loadConfig({ STACKDNS_PAYMENT_METHODS: "stripe, X402,stripe" }, []).payments.methods, ["stripe", "x402"]);
    assert.throws(() => loadConfig({ STACKDNS_PAYMENT_METHODS: "x-402" }, []), /STACKDNS_PAYMENT_METHODS: must be stripe, x402 .*x-402/);
    assert.throws(() => loadConfig({ STACKDNS_PAYMENT_METHODS: "stripe,bitcoin" }, []), /STACKDNS_PAYMENT_METHODS/);
    assert.throws(() => loadConfig({ STACKDNS_PAYMENT_METHODS: " , " }, []), /STACKDNS_PAYMENT_METHODS/);
  });
});

describe("DNS resolver lists (dns-servers-not-validated)", () => {
  it("accepts every well-formed entry Resolver.setServers takes and names the variable for anything else", () => {
    const ok = loadConfig({ STACKDNS_DNS_SERVERS: "1.1.1.1, 9.9.9.9:53,[2606:4700:4700::1111]:53,2001:4860:4860::8888,[::1],[1.1.1.1]:53,[8.8.8.8]" }, []).inspection.dnsServers;
    assert.deepEqual(ok, ["1.1.1.1", "9.9.9.9:53", "[2606:4700:4700::1111]:53", "2001:4860:4860::8888", "[::1]", "[1.1.1.1]:53", "[8.8.8.8]"]);
    // setServers only stores the list (no query is sent); every accepted entry must reach it as the address it names.
    const stored = [...ok, "[1.1.1.1]:5353"].map((entry) => {
      const resolver = new Resolver();
      resolver.setServers([entry]);
      return resolver.getServers();
    });
    assert.deepEqual(stored, [["1.1.1.1"], ["9.9.9.9"], ["2606:4700:4700::1111"], ["2001:4860:4860::8888"], ["::1"], ["1.1.1.1"], ["8.8.8.8"], ["1.1.1.1:5353"]]);
    assert.throws(() => loadConfig({ STACKDNS_DNS_SERVERS: "1.1.1.1 8.8.8.8" }, []), /STACKDNS_DNS_SERVERS entry "1\.1\.1\.1 8\.8\.8\.8" is not an IP address/);
    assert.throws(() => loadConfig({ STACKDNS_DNS_SERVERS: "dns.google" }, []), /STACKDNS_DNS_SERVERS entry "dns\.google"/);
    assert.throws(() => loadConfig({ STACKDNS_DNS_FALLBACK_SERVERS: "1.1.1.1,one.one" }, []), /STACKDNS_DNS_FALLBACK_SERVERS entry "one\.one"/);
    assert.deepEqual(loadConfig({ STACKDNS_DNS_FALLBACK_SERVERS: "off" }, []).inspection.dnsFallbackServers, [], "none/off still mean an empty list");
  });

  it("refuses ports setServers would abort on or silently rewrite", () => {
    // setServers(["1.1.1.1:0"]) fails a native assertion and kills the process; 70000 wraps to 4464.
    for (const bad of ["1.1.1.1:0", "1.1.1.1:70000", "1.1.1.1:", "1.1.1.1:abc", "[::1]:0", "[1.1.1.1]:0", "[1.1.1.1]:70000", "[1.1.1.1]:", "[1.1.1]:53", "[::1]x", "::1:53x", ""]) {
      assert.equal(isResolverAddress(bad), false, bad);
    }
    for (const good of ["8.8.8.8", "8.8.8.8:5353", "::1", "[::1]:65535", "fe80::1", "[1.1.1.1]", "[1.1.1.1]:53"]) assert.equal(isResolverAddress(good), true, good);
  });
});

describe("command-line flags (cli-flags-undocumented-unvalidated)", () => {
  it("applies valid flags, including the --sse/--remote aliases and --flag=value", () => {
    const config = loadConfig({}, ["--sse", "--port", "8080", "--host", "127.0.0.1", "--log-level", "debug"]);
    assert.equal(config.transport, "http");
    assert.equal(config.http.port, 8080);
    assert.equal(config.http.host, "127.0.0.1");
    assert.equal(config.logLevel, "debug");
    assert.equal(loadConfig({}, ["--remote"]).transport, "http");
    assert.equal(loadConfig({ STACKDNS_TRANSPORT: "http" }, ["--stdio"]).transport, "stdio");
    const eq = loadConfig({}, ["--port=4000", "--log-level=warn"]);
    assert.equal(eq.http.port, 4000);
    assert.equal(eq.logLevel, "warn");
    assert.equal(loadConfig({}, ["--unknown-wrapper-flag"]).transport, "stdio", "unrecognised arguments are still ignored");
  });

  it("fails startup on a bad or missing value instead of falling back to the default", () => {
    assert.throws(() => loadConfig({}, ["--port", "abc"]), /--port must be an integer 1-65535 \(got "abc"\)/);
    assert.throws(() => loadConfig({}, ["--port", "0"]), /--port must be an integer/);
    assert.throws(() => loadConfig({}, ["--port", "70000"]), /--port must be an integer/);
    assert.throws(() => loadConfig({}, ["--port=3.5"]), /--port must be an integer/);
    assert.throws(() => loadConfig({}, ["--log-level", "loud"]), /--log-level must be one of debug, info, warn, error, silent \(got "loud"\)/);
    assert.throws(() => loadConfig({}, ["--port"]), /--port needs a value/);
    assert.throws(() => loadConfig({}, ["--port", "--http"]), /--port needs a value/, "a following flag is never swallowed as the value");
    assert.throws(() => loadConfig({}, ["--host", ""]), /--host needs a value/);
    assert.throws(() => loadConfig({}, ["--log-level="]), /--log-level needs a value/);
  });
});

describe("output schema descriptions", () => {
  it("documents unknown and inherited email policies without changing the live enums (verify-output-unknown-policy-undocumented)", () => {
    const spf = VerifyEmailInfrastructureOutputSchema.shape.spf.shape;
    const dmarc = VerifyEmailInfrastructureOutputSchema.shape.dmarc.shape;
    assert.deepEqual(spf.allPolicy.options, ["fail", "softfail", "neutral", "pass", "none"], "the live enum is unchanged");
    assert.match(spf.allPolicy.description ?? "", /redirect= target whose lookup failed/);
    assert.match(spf.allPolicy.description ?? "", /SPF_DNS_ERROR/);
    assert.match(dmarc.inheritedFromOrganizationalDomain.description ?? "", /DMARC_DNS_ERROR/);
    assert.match(dmarc.inheritedFromOrganizationalDomain.description ?? "", /own policy is unknown/);
    assert.match(dmarc.effectivePolicy.description ?? "", /Not the subdomain's own policy/);
    assert.deepEqual(dmarc.effectivePolicy.unwrap().options, ["none", "quarantine", "reject"]);
  });

  it("documents the stored and bulk policy values, including unknown (snapshot-and-bulk-policy-values-undocumented)", () => {
    const snapshot = EmailSnapshotSchema.shape;
    assert.match(snapshot.spfPolicy.description ?? "", /unknown when an SPF redirect= target's lookup failed/);
    assert.match(snapshot.dmarcPolicy.description ?? "", /unknown when a subdomain's own _dmarc lookup failed/);
    assert.match(snapshot.dmarcPolicy.description ?? "", /null when there is no record/);
    const result = JobItemSchema.shape.result.description ?? "";
    for (const value of ["missing", "unknown", "invalid", "null MX (no mail)"]) assert.ok(result.includes(value), `bulk result describe names ${value}`);
  });

  it("counts an accepted persistent failure toward a usable score (email-snapshot-score-describe-omits-accepted)", () => {
    assert.match(EmailSnapshotSchema.shape.score.description ?? "", /accepted as persistent/);
  });

  it("says lookupsFailing fields turn into the failed reading once accepted, and DMARC stays unverified on a fallback answer (snapshot-lookupsfailing-describe-accepted)", () => {
    const failing = EmailSnapshotSchema.shape.lookupsFailing.description ?? "";
    assert.match(failing, /last known values while the failure is held/);
    assert.match(failing, /current \(failed\) reading once it was accepted as persistent \(three scans over at least a day\)/);
    const unverified = EmailSnapshotSchema.shape.unverified.description ?? "";
    assert.match(unverified, /not the domain's real posture/);
    assert.match(unverified, /DMARC stays here while only the organizational fallback of a failed own _dmarc lookup has answered/);
  });

  it("says an accepted never-answered failure leaves unverified, and how SPF behind a lame redirect= target is baselined (r10-platform-unverified-describe-accepted)", () => {
    const unverified = EmailSnapshotSchema.shape.unverified.description ?? "";
    assert.doesNotMatch(unverified, /^Components no lookup has answered yet/, "an accepted failure leaves the list although no lookup ever answered it");
    assert.match(unverified, /no lookup has answered them and their failure has not yet been accepted as persistent \(three scans over at least a day\)/);
    assert.match(unverified, /does not mean every component has answered: check lookupsFailing/);
    assert.match(unverified, /Even once accepted, DMARC stays here/);
    assert.match(unverified, /SPF whose redirect= target has never answered leaves this list once the failure is accepted \(spfPolicy reads unknown\)/);
    assert.match(unverified, /the first scan in which the whole redirect= chain answers is a baseline, not a change, for the terminal policy and the findings that describe it/);
    assert.match(EmailSnapshotSchema.shape.lookupsFailing.description ?? "", /A component also listed in unverified has no last known value/);
  });

  it("says the redirect= target's first reads re-baseline the score too, and only while the record still delegates to it (r11-platform-unverified-describe-omits-score-baseline)", () => {
    const unverified = EmailSnapshotSchema.shape.unverified.description ?? "";
    // The policy and the include tree can be first read in different scans (an include behind the target can fail in the first one), and
    // r12-trust-multihop-tree-compared-before-first-read: a later hop whose failure is accepted lets the tree be read before the policy.
    assert.match(unverified, /the first such scan with spfLookups established is the include tree's baseline; until then,/);
    // r12v-trust-partial-read-rebaselines-every-scan: only the first such reading; a later hop that stays lame must not silence every later change.
    assert.match(unverified, /the first reading in which the target answered but a later hop's failure was accepted is a baseline too, and later such readings are compared with it\./);
    assert.doesNotMatch(unverified, /any reading in which the target answered/);
    // The score is not compared in those scans, so a score_drop another component causes there goes unreported too.
    assert.match(unverified, /Each also re-baselines the score: no score_drop or score_rise for that scan or, when another lookup failed in it, for the next scan that rewrites the score/);
    // A record that stops handing its policy to the awaited target is compared as usual, and (r12-trust-accepted-apex-failure-keeps-tree-marker)
    // an accepted failure of its own lookup is a removal, not a pause in the delegation.
    assert.match(unverified, /including its removal \(an accepted failure of its own TXT lookup reads as one\) and one that stops delegating to that target\. While the record still delegates to it,/);
  });

  it("describes what the store actually reports for a never-answered failure once it is accepted (r10-platform-unverified-describe-accepted)", async () => {
    const storage = await openStorage(loadConfig({ STACKDNS_DB_FILE: ":memory:" }, []));
    assert.ok(storage);
    try {
      const HOUR = 3600000;
      const selectors = ["google", "selector1", "k1"];
      const scan = (domain: string, opts: { mtaStsFails?: boolean; redirect?: "fails" | "answers" }): EmailScanInput => {
        const policy = opts.mtaStsFails ? { fetched: false, mode: null, error: "HTTP 503", failure: "transient" } : { fetched: true, mode: "enforce", error: null, failure: null };
        const target = "_spf.provider.example";
        const spf =
          opts.redirect === undefined
            ? { found: true, valid: true, allPolicy: "fail", allQualifier: "-", redirect: null, includeChain: [] }
            : opts.redirect === "fails"
              ? { found: true, valid: true, allPolicy: "none", allQualifier: null, redirect: target, includeChain: [{ domain: target, error: "DNS error: SERVFAIL" }] }
              : { found: true, valid: true, allPolicy: "fail", allQualifier: "-", redirect: target, includeChain: [{ domain: target, error: null }] };
        return {
          domain,
          score: 85,
          grade: "A",
          mx: { found: true, nullMx: false, provider: "Google Workspace", dnsError: null },
          spf,
          dmarc: { found: true, effectivePolicy: "reject" },
          dkim: { checkedSelectors: selectors, selectors: selectors.map((selector) => ({ selector, found: selector === "google", revoked: false, error: null })) },
          mtaSts: { policy },
          risks: opts.redirect === "fails" ? [{ code: "SPF_DNS_ERROR", severity: "medium" }] : []
        } as unknown as EmailScanInput;
      };
      const snapshot = (domain: string) => {
        const email = storage.scans.history(domain).email;
        assert.ok(email);
        return email;
      };

      // (A) An MTA-STS fetch that has never answered: unverified empties once the failure is accepted, so lookupsFailing is what still flags it.
      for (const at of [0, 12]) storage.scans.recordEmail(scan("never.example", { mtaStsFails: true }), "monitor", at * HOUR);
      assert.deepEqual(snapshot("never.example").unverified, ["mtaSts", "score"]);
      storage.scans.recordEmail(scan("never.example", { mtaStsFails: true }), "monitor", 25 * HOUR);
      const accepted = snapshot("never.example");
      assert.deepEqual({ unverified: accepted.unverified, lookupsFailing: accepted.lookupsFailing, mtaStsMode: accepted.mtaStsMode }, { unverified: [], lookupsFailing: ["mtaSts"], mtaStsMode: null });

      // (B) An SPF record whose redirect= target has never answered: SPF leaves unverified once accepted, with the policy unknown.
      for (const at of [0, 12]) storage.scans.recordEmail(scan("redir.example", { redirect: "fails" }), "monitor", at * HOUR);
      assert.deepEqual(snapshot("redir.example").unverified, ["score", "spf", "spfLookups"]);
      storage.scans.recordEmail(scan("redir.example", { redirect: "fails" }), "monitor", 25 * HOUR);
      const lame = snapshot("redir.example");
      assert.deepEqual({ unverified: lame.unverified, failing: lame.lookupsFailing, spfPolicy: lame.spfPolicy }, { unverified: [], failing: ["spf", "spfLookups"], spfPolicy: "unknown" });
      // The target's first answer is a baseline for the policy and its include tree, not a change.
      const firstAnswer = storage.scans.recordEmail(scan("redir.example", { redirect: "answers" }), "monitor", 40 * HOUR);
      assert.deepEqual(firstAnswer, []);
      assert.equal(snapshot("redir.example").spfPolicy, "fail");
      // While the target stays lame, changes to the domain's own record are still reported.
      for (const at of [0, 12, 25]) storage.scans.recordEmail(scan("gone.example", { redirect: "fails" }), "monitor", at * HOUR);
      const removed = scan("gone.example", {});
      Object.assign(removed, { spf: { found: false, valid: false, allPolicy: "none", allQualifier: null, redirect: null, includeChain: [] }, risks: [{ code: "SPF_MISSING", severity: "high" }] });
      const changes = storage.scans.recordEmail(removed, "monitor", 26 * HOUR).map((c) => [c.change, c.subject, c.severity]);
      assert.deepEqual(
        changes.filter(([change]) => change === "spf_removed" || change === "risk_new"),
        [
          ["spf_removed", "spf", "high"],
          ["risk_new", "SPF_MISSING", "high"]
        ]
      );

      // (C) r11: the score is re-baselined with the target's first answer, so a DMARC drop in that scan records no score_drop
      // (a domain whose target always answered does), and a first answer whose scan could not rewrite the score moves that to
      // the next scan that does.
      const kinds = (list: Array<{ change: string }>) => list.map((c) => c.change);
      const dmarcDrop = (domain: string) =>
        Object.assign(scan(domain, { redirect: "answers" }), { score: 60, dmarc: { found: true, effectivePolicy: "none" }, risks: [{ code: "DMARC_POLICY_NONE", severity: "high" }] });
      for (const at of [0, 12, 25]) storage.scans.recordEmail(scan("first-read.example", { redirect: "fails" }), "monitor", at * HOUR);
      for (const at of [0, 12, 25]) storage.scans.recordEmail(scan("always.example", { redirect: "answers" }), "monitor", at * HOUR);
      assert.deepEqual(kinds(storage.scans.recordEmail(dmarcDrop("first-read.example"), "monitor", 40 * HOUR)), ["dmarc_policy", "risk_new"]);
      assert.deepEqual(kinds(storage.scans.recordEmail(dmarcDrop("always.example"), "monitor", 40 * HOUR)), ["dmarc_policy", "risk_new", "score_drop"]);
      for (const at of [0, 12, 25]) storage.scans.recordEmail(scan("deferred.example", { redirect: "fails" }), "monitor", at * HOUR);
      const tlsRptTimeout = Object.assign(scan("deferred.example", { redirect: "answers" }), { risks: [{ code: "TLS_RPT_DNS_ERROR", severity: "low" }] });
      assert.deepEqual(storage.scans.recordEmail(tlsRptTimeout, "monitor", 40 * HOUR), []);
      assert.deepEqual(kinds(storage.scans.recordEmail(dmarcDrop("deferred.example"), "monitor", 41 * HOUR)), ["dmarc_policy", "risk_new"]);
      // A record that stops delegating to the awaited target (here +all of its own) is compared as usual, score included.
      for (const at of [0, 12, 25]) storage.scans.recordEmail(scan("replaced.example", { redirect: "fails" }), "monitor", at * HOUR);
      const ownPassAll = Object.assign(scan("replaced.example", {}), {
        score: 65,
        spf: { found: true, valid: true, allPolicy: "pass", allQualifier: "+", redirect: null, includeChain: [] },
        risks: [{ code: "SPF_PASS_ALL", severity: "critical" }]
      });
      assert.deepEqual(kinds(storage.scans.recordEmail(ownPassAll, "monitor", 26 * HOUR)), ["spf_policy", "risk_new", "score_drop"]);
    } finally {
      storage.close();
    }
  });

  it("classifies MTA-STS certificate errors as definitive (mta-sts-failure-describe-wrong)", () => {
    const failure = VerifyEmailInfrastructureOutputSchema.shape.mtaSts.shape.policy.shape.failure.description ?? "";
    const [transient = "", definitive = ""] = failure.split(" or definitive ");
    assert.doesNotMatch(transient, /TLS/, "an invalid certificate is not a transient failure");
    assert.match(definitive, /invalid certificate/);
    assert.match(definitive, /private address/);
    assert.match(definitive, /redirect/);
    assert.match(transient, /408\/425\/429\/5xx/);
  });

  it("explains billing.creditsCharged for start_bulk_check and plan keys (billing-credits-charged-bulk)", () => {
    const text = BillingSchema.shape.creditsCharged.description ?? "";
    assert.match(text, /start_bulk_check/);
    assert.match(text, /job\.creditsCharged/);
    assert.match(text, /plan keys/);
  });

  it("states that a mostly-invalid list is refused (bulk-domains-describe-omits-rejection)", () => {
    assert.match(StartBulkCheckInputSchema.shape.domains.description ?? "", /refused with INVALID_ARGUMENT/);
    assert.match(startBulkCheckInputSchema(1000).shape.domains.description ?? "", /max\(100, accepted domains\)/);
  });
});

describe("tool surface", () => {
  it("derives the bulk list cap and the fetch deadline from config (bulk-max-domains-unreachable, tech-fetch-deadline-misstated)", async () => {
    const { client, close } = await mcpClient(loadConfig({ STACKDNS_DB_FILE: ":memory:", STACKDNS_BULK_MAX_DOMAINS: "30000", STACKDNS_FETCH_TIMEOUT_MS: "5000" }, []));
    try {
      const { tools } = await client.listTools();
      const byName = new Map(tools.map((t) => [t.name, t]));
      const start = byName.get("start_bulk_check");
      assert.ok(start);
      const domains = (start.inputSchema.properties as Record<string, { maxItems?: number; description?: string }>).domains;
      assert.equal(domains?.maxItems, 60000, "2 x the job maximum, above the old fixed 50000 cap the REST API never had");
      assert.match(domains?.description ?? "", /At most 30000 distinct domains per job, in at most 60000 entries/);
      assert.match(start.description ?? "", /refused with INVALID_ARGUMENT/);
      assert.match(start.description ?? "", /not in billing\.creditsCharged/);
      const inspect = byName.get("inspect_tech_stack")?.description ?? "";
      assert.match(inspect, /5-second deadline per attempt, at most 10 s including the insecure-TLS retry and the http:\/\/ fallback/);
      assert.doesNotMatch(inspect, /3-second hard deadline/);
      assert.match(byName.get("get_bulk_check")?.description ?? "", /null MX \(no mail\)/);
    } finally {
      await close();
    }
  });

  it("lets a list just over the job bound reach LIMIT_EXCEEDED instead of a plain-text schema rejection (bulk-schema-cap-hides-limit-exceeded)", async () => {
    const { client, close } = await mcpClient(loadConfig({ STACKDNS_DB_FILE: ":memory:" }, []));
    try {
      const start = (await client.listTools()).tools.find((t) => t.name === "start_bulk_check");
      const domains = (start?.inputSchema.properties as Record<string, { maxItems?: number; description?: string }>).domains;
      assert.equal(domains?.maxItems, 50000, "the hard cap never drops below the old fixed 50000");
      assert.match(domains?.description ?? "", /At most 1000 distinct domains per job, in at most 2000 entries; a list over either limit \(up to 50000 entries\) is refused with LIMIT_EXCEEDED/);
      const result = await client.callTool({ name: "start_bulk_check", arguments: { check: "email", domains: Array.from({ length: 2001 }, (_, i) => `d${i}.example`) } });
      assert.equal(result.isError, true);
      const text = (result.content as Array<{ type: string; text: string }>)[0]?.text ?? "";
      assert.doesNotMatch(text, /MCP error -32602/, "not the SDK's plain-text schema rejection");
      const error = (JSON.parse(text) as { error: { code: string; details: { maxDomains?: number } } }).error;
      assert.equal(error.code, "LIMIT_EXCEEDED", text);
      assert.equal(error.details.maxDomains, 1000, "the agent can read the bound and split the list");
    } finally {
      await close();
    }
    // Above 25000 domains the cap is the bound itself, so the describe does not promise LIMIT_EXCEEDED for longer lists.
    const big = startBulkCheckInputSchema(30000).shape.domains.description ?? "";
    assert.match(big, /in at most 60000 entries; more distinct domains are refused with LIMIT_EXCEEDED/);
  });

  it("documents the plain-text schema rejection the SDK returns before a tool runs (input-validation-errors-not-enveloped)", async () => {
    const { client, close } = await mcpClient(loadConfig({ STACKDNS_DB_FILE: ":memory:" }, []));
    try {
      const instructions = client.getInstructions() ?? "";
      assert.match(instructions, /plain-text isError result \("MCP error -32602: \.\.\."\) that has no error object/);
      assert.match(instructions, /\{code, message, retryable, details\}/);
      assert.equal(instructions, serverInstructions({ history: true, bulk: true, monitor: true, reverse: false }));
      // The documented behaviour is the real one: an empty domain is a schema rejection, not INVALID_DOMAIN.
      const result = await client.callTool({ name: "verify_email_infrastructure", arguments: { domain: "  " } });
      assert.equal(result.isError, true);
      assert.equal(result.structuredContent, undefined);
      const text = (result.content as Array<{ type: string; text: string }>)[0]?.text ?? "";
      assert.match(text, /^MCP error -32602: /);
      assert.throws(() => JSON.parse(text));
    } finally {
      await close();
    }
  });
});

describe("HTTP transport", () => {
  const open: HttpHarness[] = [];
  after(async () => {
    for (const h of open) await h.close();
  });
  const harness = async (env: Record<string, string> = {}, options: { selfServe?: boolean } = {}): Promise<HttpHarness> => {
    const h = await httpHarness(env, options);
    open.push(h);
    return h;
  };
  const authed = { authorization: `Bearer ${ENTERPRISE_KEY}` };

  it("answers REST body-parser failures in the tool error shape and keeps JSON-RPC on /mcp (rest-parser-and-auth-error-shape)", async () => {
    const h = await harness({ STACKDNS_API_KEYS: `${ENTERPRISE_KEY}:enterprise:ops` });
    const rest = await fetch(`${h.base}/v1/jobs`, { method: "POST", headers: { "content-type": "application/json", ...authed }, body: "{not json" });
    assert.equal(rest.status, 400);
    assert.deepEqual(await rest.json(), { error: { code: "INVALID_ARGUMENT", message: "Request body is not valid JSON.", retryable: false, details: {} } });
    const mcp = await fetch(`${h.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...authed }, body: "{not json" });
    assert.equal(mcp.status, 400);
    const rpc = (await mcp.json()) as { jsonrpc?: string; error?: { code?: number } };
    assert.equal(rpc.jsonrpc, "2.0");
    assert.equal(rpc.error?.code, -32700);
    const unknown = await fetch(`${h.base}/v1/nope`, { headers: authed });
    assert.equal(unknown.status, 404);
    assert.equal(((await unknown.json()) as { error: { code: string } }).error.code, "NOT_FOUND");
  });

  it("answers an oversized REST body with LIMIT_EXCEEDED in the tool error shape (bulk-max-exceeds-http-body-limit)", async () => {
    const h = await harness({ STACKDNS_API_KEYS: `${ENTERPRISE_KEY}:enterprise:ops` });
    const json = await fetch(`${h.base}/v1/jobs`, { method: "POST", headers: { "content-type": "application/json", ...authed }, body: JSON.stringify({ domains: ["x".repeat(MIB + 10)] }) });
    assert.equal(json.status, 413);
    const body = (await json.json()) as { error: { code: string; message: string; retryable: boolean; details: { limitBytes?: number } } };
    assert.equal(body.error.code, "LIMIT_EXCEEDED");
    assert.equal(body.error.retryable, false);
    assert.equal(body.error.details.limitBytes, MIB);
    assert.match(body.error.message, /JSON 1 MiB, CSV 2 MiB/);
    const csv = await fetch(`${h.base}/v1/jobs?check=email`, { method: "POST", headers: { "content-type": "text/csv", ...authed }, body: "a.example\n".repeat(Math.ceil((2 * MIB) / 10) + 10) });
    assert.equal(csv.status, 413);
    assert.equal(((await csv.json()) as { error: { code: string } }).error.code, "LIMIT_EXCEEDED");
  });

  it("sizes the body limits from STACKDNS_BULK_MAX_DOMAINS so the largest accepted list fits (bulk-max-exceeds-http-body-limit)", async () => {
    assert.deepEqual(httpBodyLimits(1000), { json: MIB, text: 2 * MIB }, "the default keeps the old 1 MiB / 2 MiB limits");
    assert.deepEqual(httpBodyLimits(50000), { json: 6400000, text: 6400000 });
    const h = await harness({ STACKDNS_API_KEYS: `${ENTERPRISE_KEY}:enterprise:ops`, STACKDNS_BULK_MAX_DOMAINS: "20000" });
    // 20000 distinct URLs of about 70 characters: over the old fixed 1 MiB, inside the derived limit.
    const domains = Array.from({ length: 20000 }, (_, i) => `https://www.round8-platform-company-${String(i).padStart(6, "0")}.com/pricing/enterprise`);
    const payload = JSON.stringify({ domains, check: "email" });
    assert.ok(payload.length > MIB, `payload is ${payload.length} bytes`);
    const res = await fetch(`${h.base}/v1/jobs`, { method: "POST", headers: { "content-type": "application/json", ...authed }, body: payload });
    const body = (await res.json()) as { job?: { accepted: number }; error?: unknown };
    assert.equal(res.status, 202, JSON.stringify(body.error));
    assert.equal(body.job?.accepted, 20000);
  });

  it("exposes X-Payment-Status, Location and Content-Disposition to browsers (cors-expose-missing-payment-status)", async () => {
    for (const header of ["X-Payment-Status", "Location", "Content-Disposition"]) assert.ok(EXPOSED_HEADERS.split(", ").includes(header), header);
    const h = await harness();
    const res = await fetch(`${h.base}/healthz`, { headers: { origin: "https://app.example" } });
    const exposed = res.headers.get("access-control-expose-headers") ?? "";
    assert.match(exposed, /X-Payment-Status/);
    assert.match(exposed, /Location/);
    assert.match(exposed, /Content-Disposition/);
    await res.body?.cancel();
  });

  it("refuses an unknown ?status or a malformed ?offset/?limit on GET /v1/jobs/:id (rest-get-job-ignores-bad-status)", async () => {
    const h = await harness({ STACKDNS_API_KEYS: `${ENTERPRISE_KEY}:enterprise:ops` });
    const id = "job_0123456789abcdef01234567";
    const bad = await fetch(`${h.base}/v1/jobs/${id}?status=faild`, { headers: authed });
    assert.equal(bad.status, 400);
    const error = ((await bad.json()) as { error: { code: string; message: string } }).error;
    assert.equal(error.code, "INVALID_ARGUMENT");
    assert.match(error.message, /status must be one of pending, running, done, failed, skipped, cancelled/);
    const repeated = await fetch(`${h.base}/v1/jobs/${id}?status=failed&status=done`, { headers: authed });
    assert.equal(repeated.status, 400);
    await repeated.body?.cancel();
    const limit = await fetch(`${h.base}/v1/jobs/${id}?limit=abc`, { headers: authed });
    assert.equal(limit.status, 400);
    assert.match(((await limit.json()) as { error: { message: string } }).error.message, /limit must be a non-negative integer/);
    const listLimit = await fetch(`${h.base}/v1/jobs?limit=-3`, { headers: authed });
    assert.equal(listLimit.status, 400);
    await listLimit.body?.cancel();
    const mixed = await fetch(`${h.base}/v1/jobs/${id}?status=failed&limit=10&status=`, { headers: authed });
    assert.equal(mixed.status, 400, "a repeated status is refused even when one copy is empty");
    await mixed.body?.cancel();
    const unknownJob = await fetch(`${h.base}/v1/jobs/${id}?status=failed&offset=0&limit=`, { headers: authed });
    assert.equal(unknownJob.status, 404, "a valid filter reaches the job lookup");
    await unknownJob.body?.cancel();
  });

  it('does not let a "*" origin refuse every browser under DNS-rebinding protection (rebinding-wildcard-origin)', async () => {
    const options = (allowedOrigins: string[], allowedHosts: string[] = []) => rebindingProtection({ enableDnsRebindingProtection: true, allowedHosts, allowedOrigins });
    assert.deepEqual(options(["*"]), { enableDnsRebindingProtection: true, allowedHosts: undefined, allowedOrigins: undefined });
    assert.equal(options(["https://app.example", "*"], ["localhost:3333"]).allowedOrigins, undefined, '"*" in a mixed list allows every origin, as CORS and the anonymous-origin check read it');
    assert.deepEqual(options(["https://app.example"], ["localhost:3333"]), { enableDnsRebindingProtection: true, allowedHosts: ["localhost:3333"], allowedOrigins: ["https://app.example"] });
    const initialize = (h: HttpHarness, origin: string): Promise<Response> =>
      fetch(`${h.base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", origin, ...authed },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "round8-platform", version: "1.0.0" } } })
      });
    const keys = { STACKDNS_API_KEYS: `${ENTERPRISE_KEY}:enterprise:ops`, STACKDNS_DNS_REBINDING_PROTECTION: "true" };
    const wildcard = await harness({ ...keys, STACKDNS_ALLOWED_ORIGINS: "*" });
    const allowed = await initialize(wildcard, "https://app.example");
    const allowedBody = await allowed.text();
    assert.equal(allowed.status, 200, allowedBody);
    assert.doesNotMatch(allowedBody, /Invalid Origin header/);
    // Without "*" the listed origins still gate the MCP endpoints.
    const listed = await harness({ ...keys, STACKDNS_ALLOWED_ORIGINS: "https://app.example" });
    const refused = await initialize(listed, "https://other.example");
    assert.equal(refused.status, 403);
    assert.match(await refused.text(), /Invalid Origin header: https:\/\/other\.example/);
  });

  it("warns that protection without STACKDNS_ALLOWED_HOSTS checks no Host header (rebinding-no-hosts-warning)", async () => {
    const bare = await captureLogs("warn", () => harness({ STACKDNS_DNS_REBINDING_PROTECTION: "true" }));
    assert.ok(
      bare.lines.some((l) => l.includes("STACKDNS_DNS_REBINDING_PROTECTION is on but STACKDNS_ALLOWED_HOSTS is empty, so the Host header is not checked")),
      bare.lines.join("")
    );
    const hosts = await captureLogs("warn", () => harness({ STACKDNS_DNS_REBINDING_PROTECTION: "true", STACKDNS_ALLOWED_HOSTS: "127.0.0.1:3333" }));
    assert.equal(
      hosts.lines.some((l) => l.includes("STACKDNS_ALLOWED_HOSTS is empty")),
      false,
      hosts.lines.join("")
    );
    const off = await captureLogs("warn", () => harness());
    assert.equal(
      off.lines.some((l) => l.includes("STACKDNS_ALLOWED_HOSTS is empty")),
      false,
      "no warning while protection is off"
    );
    const wildcard = await captureLogs("warn", () => harness({ STACKDNS_DNS_REBINDING_PROTECTION: "true", STACKDNS_ALLOWED_HOSTS: "127.0.0.1:3333", STACKDNS_ALLOWED_ORIGINS: "*" }));
    assert.ok(
      wildcard.lines.some((l) => l.includes('STACKDNS_ALLOWED_ORIGINS contains \\"*\\", so DNS-rebinding protection does not check the Origin header')),
      wildcard.lines.join("")
    );
  });

  it("does not warn that every request is rejected when self-serve signup sells keys (http-warning-ignores-selfserve)", async () => {
    const quiet = await captureLogs("warn", () => harness({}, { selfServe: true }));
    assert.equal(
      quiet.lines.some((l) => l.includes("every authenticated route will answer 401") || l.includes("every request will be rejected")),
      false,
      quiet.lines.join("")
    );
    const locked = await captureLogs("warn", () => harness());
    assert.ok(
      locked.lines.some((l) => l.includes("auth is required but no API keys, payment methods or self-serve signup are configured; every authenticated route will answer 401")),
      locked.lines.join("")
    );
  });
});
