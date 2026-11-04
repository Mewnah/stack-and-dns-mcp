import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseDomain, registrableDomain, stripWww } from "../src/lib/domain.js";

describe("parseDomain", () => {
  it("normalizes URLs, case and paths", () => {
    const result = parseDomain("https://WWW.Example.COM/pricing?utm=1#top");
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.domain, "www.example.com");
      assert.equal(result.registrable, "example.com");
      assert.equal(result.isSubdomain, true);
    }
  });

  it("accepts email addresses and ports", () => {
    const email = parseDomain("jane@Sub.Example.co.uk");
    assert.equal(email.ok, true);
    if (email.ok) {
      assert.equal(email.domain, "sub.example.co.uk");
      assert.equal(email.registrable, "example.co.uk");
    }
    const port = parseDomain("example.com:8443");
    assert.equal(port.ok && port.domain, "example.com");
  });

  it("converts IDN names to punycode", () => {
    const result = parseDomain("bücher.de");
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.domain, "xn--bcher-kva.de");
      assert.equal(result.unicode, "bücher.de");
    }
  });

  it("rejects IP literals, single labels and garbage", () => {
    for (const input of ["127.0.0.1", "http://10.0.0.1/admin", "[::1]", "localhost", "not a domain", "", "   ", "a..b.com", "-bad.com"]) {
      const result = parseDomain(input);
      assert.equal(result.ok, false, `expected ${JSON.stringify(input)} to be rejected`);
      if (!result.ok) assert.equal(result.code, "INVALID_DOMAIN");
    }
  });

  it("flags reserved and private TLDs", () => {
    for (const input of ["intranet.corp", "printer.local", "db.internal", "foo.test", "site.example"]) {
      const result = parseDomain(input);
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.code, "PRIVATE_TARGET");
    }
    const allowed = parseDomain("printer.local", { allowPrivate: true });
    assert.equal(allowed.ok, true);
  });

  it("enforces DNS length limits", () => {
    const longLabel = `${"a".repeat(64)}.com`;
    assert.equal(parseDomain(longLabel).ok, false);
    const longName = `${Array.from({ length: 30 }, () => "abcdefghi").join(".")}.com`;
    assert.equal(parseDomain(longName).ok, false);
  });
});

describe("registrableDomain / stripWww", () => {
  it("handles multi-part public suffixes", () => {
    assert.equal(registrableDomain("mail.acme.co.uk"), "acme.co.uk");
    assert.equal(registrableDomain("shop.acme.com.au"), "acme.com.au");
    assert.equal(registrableDomain("a.b.c.example.com"), "example.com");
    assert.equal(registrableDomain("example.com"), "example.com");
    assert.equal(registrableDomain("mystore.myshopify.com"), "mystore.myshopify.com");
  });

  it("strips only a leading www label", () => {
    assert.equal(stripWww("www.example.com"), "example.com");
    assert.equal(stripWww("www.com"), "www.com");
    assert.equal(stripWww("wwwexample.com"), "wwwexample.com");
  });
});
