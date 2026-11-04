import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assertPublicLiteral, isPrivateTargetError } from "../src/lib/lookup.js";
import { inspectTls } from "../src/lib/tls.js";

describe("assertPublicLiteral", () => {
  it("refuses IP literals in private space in every spelling sockets accept", () => {
    for (const host of ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "[::1]", "::ffff:127.0.0.1", "[::ffff:10.0.0.1]", "fe80::1%eth0", "[fe80::1%25eth0]", "::127.0.0.1", "64:ff9b::a00:1"]) {
      assert.throws(
        () => assertPublicLiteral(host, false),
        (err: unknown) => isPrivateTargetError(err),
        host
      );
    }
  });

  it("allows public literals, hostnames, and everything when private targets are permitted", () => {
    for (const host of ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "example.com", "localhost", "2130706433"]) {
      assert.doesNotThrow(() => assertPublicLiteral(host, false), host);
    }
    assert.doesNotThrow(() => assertPublicLiteral("127.0.0.1", true));
  });
});

describe("inspectTls private literals", () => {
  it("refuses a private IP-literal host before opening a socket", async () => {
    for (const host of ["127.0.0.1", "[::1]", "::ffff:169.254.169.254"]) {
      const started = Date.now();
      const result = await inspectTls(host, { timeoutMs: 3000, allowPrivate: false, port: 1 });
      assert.equal(result.reachable, false, host);
      assert.equal(result.error?.code, "EPRIVATETARGET", host);
      assert.ok(Date.now() - started < 500, `${host}: no connection attempt was made`);
    }
  });
});
