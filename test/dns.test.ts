import assert from "node:assert/strict";
import type { Resolver } from "node:dns/promises";
import { describe, it } from "node:test";
import { DnsClient } from "../src/lib/dns.js";
import { setLogLevel } from "../src/logger.js";

setLogLevel("silent");

interface ScriptedResolver {
  resolver: Resolver;
  calls: string[];
}

function errorWithCode(code: string): Error {
  return Object.assign(new Error(code), { code });
}

/** A resolver whose answers are scripted per "TYPE name" key; unknown names are NXDOMAIN. */
function scripted(answers: Record<string, unknown[] | Error>, servers = ["192.0.2.53"]): ScriptedResolver {
  const calls: string[] = [];
  const answer = (type: string, name: string): Promise<unknown[]> => {
    calls.push(`${type} ${name}`);
    const value = answers[`${type} ${name}`];
    if (value instanceof Error) return Promise.reject(value);
    if (value === undefined) return Promise.reject(errorWithCode("ENOTFOUND"));
    return Promise.resolve(value);
  };
  const resolver = {
    getServers: () => servers,
    setServers: () => undefined,
    resolveTxt: (name: string) => answer("TXT", name),
    resolveMx: (name: string) => answer("MX", name),
    resolve4: (name: string) => answer("A", name),
    resolve6: (name: string) => answer("AAAA", name),
    resolveCname: (name: string) => answer("CNAME", name),
    resolveNs: (name: string) => answer("NS", name),
    resolveCaa: (name: string) => answer("CAA", name),
    resolveSoa: (name: string) => answer("SOA", name).then((v) => v[0])
  } as unknown as Resolver;
  return { resolver, calls };
}

describe("DnsClient cache", () => {
  it("serves repeated and concurrent identical queries from one resolver call", async () => {
    const primary = scripted({ "TXT example.com": [["v=spf1 -all"]], "MX example.com": [{ exchange: "mx.example.com", priority: 10 }] });
    const dns = new DnsClient({ fallbackServers: [], resolverFactory: () => primary.resolver, timeoutMs: 500, tries: 1 });

    const [first, second] = await Promise.all([dns.txt("example.com"), dns.txt("example.com")]);
    assert.deepEqual(first.records, ["v=spf1 -all"]);
    assert.deepEqual(second.records, ["v=spf1 -all"]);
    assert.equal(primary.calls.filter((c) => c === "TXT example.com").length, 1, "concurrent identical queries are coalesced");

    const third = await dns.txt("example.com");
    assert.deepEqual(third.records, ["v=spf1 -all"]);
    assert.equal(primary.calls.filter((c) => c === "TXT example.com").length, 1, "a fresh answer is reused");
    assert.equal(dns.cacheSize, 1);

    // The existence probe followed by MX/TXT evaluations issues each apex query once.
    await dns.exists("example.com");
    await Promise.all([dns.mx("example.com"), dns.txt("example.com"), dns.a("example.com")]);
    assert.equal(primary.calls.filter((c) => c === "MX example.com").length, 1);
    assert.equal(primary.calls.filter((c) => c === "A example.com").length, 1);
  });

  it("returns copies so callers cannot corrupt the cached answer", async () => {
    const primary = scripted({
      "MX example.com": [
        { exchange: "b.example.com", priority: 20 },
        { exchange: "a.example.com", priority: 10 }
      ]
    });
    const dns = new DnsClient({ fallbackServers: [], resolverFactory: () => primary.resolver, timeoutMs: 500, tries: 1 });
    const first = await dns.mx("example.com");
    first.records.sort((x, y) => x.priority - y.priority);
    first.records.splice(0, 1);
    const second = await dns.mx("example.com");
    assert.equal(second.records.length, 2);
    assert.equal(second.records[0]?.exchange, "b.example.com");
  });

  it("does not cache errors and honours a disabled cache", async () => {
    let attempt = 0;
    const flaky = scripted({});
    const original = flaky.resolver.resolveTxt.bind(flaky.resolver);
    flaky.resolver.resolveTxt = ((name: string) => {
      attempt++;
      if (attempt === 1) return Promise.reject(errorWithCode("ESERVFAIL"));
      return original(name);
    }) as Resolver["resolveTxt"];
    const dns = new DnsClient({ fallbackServers: [], resolverFactory: () => flaky.resolver, timeoutMs: 500, tries: 1 });
    const failed = await dns.txt("flaky.example");
    assert.equal(failed.error?.code, "ESERVFAIL");
    const retried = await dns.txt("flaky.example");
    assert.equal(retried.error, null, "the failure was not cached");
    assert.equal(retried.nxdomain, true);

    const uncached = scripted({ "A example.com": ["192.0.2.1"] });
    const noCache = new DnsClient({ fallbackServers: [], resolverFactory: () => uncached.resolver, timeoutMs: 500, tries: 1, cacheTtlMs: 0 });
    await noCache.a("example.com");
    await noCache.a("example.com");
    assert.equal(uncached.calls.length, 2);
    assert.equal(noCache.cacheSize, 0);
  });
});
