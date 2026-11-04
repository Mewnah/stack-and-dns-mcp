import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseSafeInteger } from "../src/lib/numbers.js";
import { canonicalJson } from "../src/middleware/payments.js";

describe("parseSafeInteger", () => {
  it("parses plain, zero and zero-padded integers", () => {
    assert.equal(parseSafeInteger("31536000"), 31536000);
    assert.equal(parseSafeInteger("0"), 0);
    assert.equal(parseSafeInteger("000000000000000000000000031536000"), 31536000);
    assert.equal(parseSafeInteger(" 86400 "), 86400);
  });

  it("rejects malformed, negative, fractional and overflowing values", () => {
    assert.equal(parseSafeInteger(undefined), null);
    assert.equal(parseSafeInteger(""), null);
    assert.equal(parseSafeInteger("-5"), null);
    assert.equal(parseSafeInteger("1.5"), null);
    assert.equal(parseSafeInteger("1e3"), null);
    assert.equal(parseSafeInteger("9".repeat(400)), null);
    assert.equal(parseSafeInteger("9007199254740993"), null);
  });
});

describe("canonicalJson", () => {
  it("is independent of key order and nesting order", () => {
    const a = canonicalJson({ b: 1, a: { d: [1, { z: 2, y: 3 }], c: "x" } });
    const b = canonicalJson({ a: { c: "x", d: [1, { y: 3, z: 2 }] }, b: 1 });
    assert.equal(a, b);
    assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
    assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
  });

  it("refuses pathological nesting instead of overflowing the stack", () => {
    let deep: unknown = 1;
    for (let i = 0; i < 5000; i++) deep = [deep];
    assert.throws(() => canonicalJson(deep), RangeError);
  });
});
