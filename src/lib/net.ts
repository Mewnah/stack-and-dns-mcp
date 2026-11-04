/**
 * IP classification helpers used for SSRF protection. Every outbound
 * connection (HTTP, TLS) resolves through a guarded lookup that refuses
 * loopback, link-local, private, multicast, reserved and cloud metadata
 * addresses unless the operator explicitly allows private targets.
 */

import { isIP } from "node:net";

const IPV4_PRIVATE_BLOCKS: Array<[number, number]> = [
  [0x00000000, 8], // 0.0.0.0/8 current network
  [0x0a000000, 8], // 10.0.0.0/8
  [0x64400000, 10], // 100.64.0.0/10 carrier-grade NAT
  [0x7f000000, 8], // 127.0.0.0/8 loopback
  [0xa9fe0000, 16], // 169.254.0.0/16 link-local and cloud metadata endpoints
  [0xac100000, 12], // 172.16.0.0/12
  [0xc0000000, 24], // 192.0.0.0/24 IETF protocol assignments
  [0xc0000200, 24], // 192.0.2.0/24 TEST-NET-1
  [0xc0586300, 24], // 192.88.99.0/24 deprecated 6to4 relay anycast
  [0xc0a80000, 16], // 192.168.0.0/16
  [0xc6120000, 15], // 198.18.0.0/15 benchmarking
  [0xc6336400, 24], // 198.51.100.0/24 TEST-NET-2
  [0xcb007100, 24], // 203.0.113.0/24 TEST-NET-3
  [0xe0000000, 4], // 224.0.0.0/4 multicast
  [0xf0000000, 4] // 240.0.0.0/4 reserved and broadcast
];

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

export function isPrivateIPv4(ip: string): boolean {
  const value = ipv4ToInt(ip);
  if (value === null) return true;
  for (const [base, bits] of IPV4_PRIVATE_BLOCKS) {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    if ((value & mask) >>> 0 === (base & mask) >>> 0) return true;
  }
  return false;
}

export function expandIPv6(ip: string): number[] | null {
  let addr = ip.toLowerCase();
  const zoneIdx = addr.indexOf("%");
  if (zoneIdx !== -1) addr = addr.slice(0, zoneIdx);
  const lastColon = addr.lastIndexOf(":");
  if (addr.includes(".") && lastColon !== -1) {
    const embedded = ipv4ToInt(addr.slice(lastColon + 1));
    if (embedded === null) return null;
    addr = addr.slice(0, lastColon) + ":" + (embedded >>> 16).toString(16) + ":" + (embedded & 0xffff).toString(16);
  }
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array.from({ length: missing }, () => "0"), ...tail];
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

/**
 * A stable per-client network key for throttles and anonymous principals:
 * an IPv4-mapped IPv6 address becomes its IPv4 address, and a native IPv6
 * address becomes its /64 prefix (one customer typically holds a whole /64,
 * so per-address buckets would be trivial to multiply).
 */
export function clientNetworkKey(raw: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(raw);
  if (mapped) return mapped[1] as string;
  if (isIP(raw.split("%")[0] ?? raw) === 6) {
    const groups = expandIPv6(raw);
    if (groups)
      return `${groups
        .slice(0, 4)
        .map((g) => g.toString(16))
        .join(":")}::/64`;
  }
  return raw;
}

function v4FromGroups(hi: number, lo: number): string {
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

export function isPrivateIPv6(ip: string): boolean {
  const groups = expandIPv6(ip);
  if (!groups) return true;
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = groups;
  const zeroPrefix = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0;
  if (zeroPrefix && g4 === 0 && g5 === 0) return true; // ::/96: unspecified, loopback and deprecated IPv4-compatible (::a.b.c.d)
  if (zeroPrefix && g4 === 0 && g5 === 0xffff) return isPrivateIPv4(v4FromGroups(g6, g7)); // ::ffff:0:0/96 IPv4-mapped
  if (zeroPrefix && g4 === 0xffff && g5 === 0) return isPrivateIPv4(v4FromGroups(g6, g7)); // ::ffff:0:0:0/96 IPv4-translated (SIIT)
  if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return isPrivateIPv4(v4FromGroups(g6, g7)); // 64:ff9b::/96 NAT64 well-known prefix
  }
  if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0x0001) return isPrivateIPv4(v4FromGroups(g6, g7)); // 64:ff9b:1::/48 local-use NAT64
  if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return true; // 100::/64 discard-only
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g0 & 0xffc0) === 0xfec0) return true; // fec0::/10 deprecated site-local
  if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // 2001:db8::/32 documentation
  if (g0 === 0x2001 && g1 === 0x0000) return isPrivateIPv4(v4FromGroups(g6 ^ 0xffff, g7 ^ 0xffff)); // 2001::/32 Teredo: client IPv4 is stored inverted
  if (g0 === 0x2001 && (g1 & 0xfff0) === 0x0010) return true; // 2001:10::/28 ORCHID (deprecated)
  if (g0 === 0x2001 && (g1 & 0xfff0) === 0x0020) return true; // 2001:20::/28 ORCHIDv2, not routable
  if (g0 === 0x2002) return isPrivateIPv4(v4FromGroups(g1, g2)); // 6to4 embedded IPv4
  if ((g0 & 0xfff0) === 0x3ff0 && g0 === 0x3fff) return true; // 3fff::/20 documentation
  if (g0 === 0x5f00) return true; // 5f00::/16 segment-routing SIDs
  return false;
}

export function isPrivateAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPrivateIPv4(ip);
  if (family === 6) return isPrivateIPv6(ip);
  return true;
}
