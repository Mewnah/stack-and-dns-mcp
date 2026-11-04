import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ApiKeyStore, apiKeyId, generateApiKey, hashApiKey, principalFromAuthInfo, principalToAuthInfo, SessionTokenService } from "../src/middleware/auth.js";

describe("ApiKeyStore", () => {
  it("parses inline keys and verifies them by hash", () => {
    const key = generateApiKey();
    const store = new ApiKeyStore();
    for (const record of ApiKeyStore.parseInline(`${key}:pro:Acme Corp, other_key_value_1234567890:free:Trial`)) store.add(record);
    assert.equal(store.size, 2);
    const verified = store.verify(key);
    assert.ok(verified);
    assert.equal(verified.plan, "pro");
    assert.equal(verified.label, "Acme Corp");
    assert.equal(verified.id, apiKeyId(hashApiKey(key)));
    assert.equal(store.verify("sdm_live_nope_nope_nope_nope"), null);
    assert.equal(store.verify(""), null);
  });

  it("rejects invalid plans", () => {
    assert.throws(() => ApiKeyStore.parseInline("sdm_live_abcdefghijklmnop:platinum:X"), /invalid plan/);
    assert.throws(() => ApiKeyStore.parseInline("sdm_live_abcdefghijklmnop:payg:X"), /invalid plan/);
  });

  it("rejects inline and file keys that could never authenticate, without echoing them", async () => {
    assert.throws(() => ApiKeyStore.parseInline("x:pro:short"), /between 16 and 256 characters/);
    assert.throws(() => ApiKeyStore.parseInline(`${"k".repeat(257)}:pro:long`), /between 16 and 256 characters/);
    assert.throws(
      () => ApiKeyStore.parseInline("sk_super_secret:pro:x"),
      (err: unknown) => err instanceof Error && !err.message.includes("sk_super_secret") && err.message.includes('"sk_s..."')
    );
    assert.equal(ApiKeyStore.parseInline("sdm_live_0123456789abcdef:pro:ok").length, 1);

    const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const path = await import("node:path");
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-keys-"));
    try {
      const file = path.join(dir, "keys.json");
      await writeFile(file, JSON.stringify([{ key: "short", plan: "pro" }]), "utf8");
      await assert.rejects(() => ApiKeyStore.parseFile(file), /between 16 and 256 characters/);
      await writeFile(file, JSON.stringify([{ key: "sdm_live_0123456789abcdef", plan: "pro" }]), "utf8");
      assert.equal((await ApiKeyStore.parseFile(file)).length, 1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("honours the active flag", () => {
    const key = generateApiKey();
    const store = new ApiKeyStore();
    store.add({ id: "k", keyHash: hashApiKey(key), prefix: "sdm_live_", plan: "pro", label: "", active: false });
    assert.equal(store.verify(key), null);
  });
});

describe("SessionTokenService", () => {
  it("issues and verifies HMAC tokens", () => {
    const service = new SessionTokenService("test-secret-that-is-long-enough");
    const token = service.issue({ sub: "pay_abc", plan: "payg", label: "stripe:pi_1" }, 60000);
    assert.ok(token.startsWith("sdm_sess."));
    const claims = service.verify(token);
    assert.ok(claims);
    assert.equal(claims.sub, "pay_abc");
    assert.equal(claims.plan, "payg");
  });

  it("rejects tampered, foreign and expired tokens", () => {
    const service = new SessionTokenService("test-secret-that-is-long-enough");
    const other = new SessionTokenService("another-secret-that-is-long-enough");
    const token = service.issue({ sub: "pay_abc", plan: "payg", label: "" }, 60000);
    assert.equal(other.verify(token), null);
    assert.equal(service.verify(token.slice(0, -2) + "zz"), null);
    assert.equal(service.verify("sdm_sess.garbage"), null);
    const expired = service.issue({ sub: "pay_abc", plan: "payg", label: "" }, -1000);
    assert.equal(service.verify(expired), null);
  });
});

describe("AuthInfo round trip", () => {
  it("embeds and extracts the principal", () => {
    const principal = { id: "key_123", plan: "pro" as const, label: "Acme", source: "api-key" as const };
    const info = principalToAuthInfo(principal, "sdm_live_x");
    assert.deepEqual(principalFromAuthInfo(info), principal);
    assert.equal(principalFromAuthInfo(undefined), null);
    assert.equal(principalFromAuthInfo({ token: "t", clientId: "c", scopes: [], extra: { principal: { id: 1 } } }), null);
  });
});
