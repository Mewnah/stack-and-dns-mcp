import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isPrivateAddress, isPrivateIPv4, isPrivateIPv6 } from "../src/lib/net.js";

describe("isPrivateIPv4", () => {
  it("flags RFC 1918, loopback, link-local, CGNAT and reserved space", () => {
    for (const ip of [
      "10.0.0.1",
      "172.16.5.5",
      "172.31.255.255",
      "192.168.1.1",
      "127.0.0.1",
      "127.255.255.254",
      "169.254.169.254",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "240.0.0.1",
      "255.255.255.255",
      "192.0.2.10",
      "198.18.0.1"
    ]) {
      assert.equal(isPrivateIPv4(ip), true, `${ip} should be private`);
    }
  });

  it("flags the deprecated 6to4 relay anycast block", () => {
    assert.equal(isPrivateIPv4("192.88.99.1"), true);
    assert.equal(isPrivateIPv4("192.88.100.1"), false);
  });

  it("allows public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "104.16.0.1", "203.0.114.1"]) {
      assert.equal(isPrivateIPv4(ip), false, `${ip} should be public`);
    }
  });

  it("treats malformed input as private", () => {
    assert.equal(isPrivateIPv4("999.1.1.1"), true);
    assert.equal(isPrivateIPv4("1.2.3"), true);
  });
});

describe("isPrivateIPv6", () => {
  it("flags loopback, unspecified, ULA, link-local, multicast and mapped IPv4", () => {
    for (const ip of [
      "::1",
      "::",
      "fc00::1",
      "fd12:3456::1",
      "fe80::1",
      "ff02::1",
      "::ffff:10.0.0.1",
      "::ffff:127.0.0.1",
      "64:ff9b::a00:1",
      "2001:db8::1",
      "fec0::1",
      "2002:c0a8:101::1",
      "::127.0.0.1",
      "::169.254.169.254",
      "::10.0.0.1",
      "::8.8.8.8",
      "::2"
    ]) {
      assert.equal(isPrivateIPv6(ip), true, `${ip} should be private`);
    }
  });

  it("flags every transition and special-purpose prefix that can embed or reach private space", () => {
    const privateForms: Array<[string, string]> = [
      ["::ffff:0:7f00:1", "IPv4-translated loopback"],
      ["::ffff:0:a9fe:a9fe", "IPv4-translated metadata"],
      ["64:ff9b:1::7f00:1", "local-use NAT64 loopback"],
      ["100::1", "discard-only"],
      ["2001:0::ffff:80ff:fffe", "Teredo with inverted client 127.0.0.1"],
      ["2001:0:4136:e378:8000:63bf:5601:5efe", "Teredo with inverted client 169.254.161.1"],
      ["2001:10::1", "ORCHID"],
      ["2001:20::1", "ORCHIDv2"],
      ["3fff::1", "documentation"],
      ["5f00::1", "segment routing"]
    ];
    for (const [ip, label] of privateForms) assert.equal(isPrivateIPv6(ip), true, `${ip} (${label}) should be private`);
  });

  it("allows global unicast", () => {
    for (const ip of [
      "2606:4700::1111",
      "2001:4860:4860::8888",
      "::ffff:8.8.8.8",
      "64:ff9b::808:808",
      "::ffff:0:808:808",
      "64:ff9b:1::808:808",
      "2001:0::f7f7:f7f7",
      "2001:2::1",
      "2001:200::1",
      "3ffe::1",
      "5e00::1"
    ]) {
      assert.equal(isPrivateIPv6(ip), false, `${ip} should be public`);
    }
  });
});

describe("isPrivateAddress", () => {
  it("dispatches by family and rejects non-IPs", () => {
    assert.equal(isPrivateAddress("10.1.1.1"), true);
    assert.equal(isPrivateAddress("2606:4700::1111"), false);
    assert.equal(isPrivateAddress("example.com"), true);
  });
});
