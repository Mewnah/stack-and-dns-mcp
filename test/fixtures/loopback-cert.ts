/**
 * A self-signed certificate for the loopback HTTPS servers in the tests,
 * made in process: no openssl binary is needed, so the end-to-end HTTPS
 * tests run on every machine, and no private key is kept in the repository.
 * The key is generated on first use and lives only in this process.
 *
 * The certificate is a minimal X.509 v3 one (ECDSA P-256, SHA-256) with
 * subjectAltName localhost, *.test and IP 127.0.0.1, valid from a day ago
 * for a week. The clients in the tests do not verify it (the strict attempt
 * against it is expected to fail, or rejectUnauthorized is off), so only its
 * encoding has to be right for the TLS server to load it.
 */

import { generateKeyPairSync, randomBytes, sign } from "node:crypto";

const DAY = 24 * 60 * 60 * 1000;

/** One DER element: tag, definite length, contents. */
function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const n = body.length;
  let length: number[];
  if (n < 0x80) length = [n];
  else if (n < 0x100) length = [0x81, n];
  else if (n < 0x10000) length = [0x82, n >> 8, n & 0xff];
  else throw new Error("DER element too long for this encoder");
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}

const sequence = (...parts: Buffer[]): Buffer => der(0x30, ...parts);
const set = (...parts: Buffer[]): Buffer => der(0x31, ...parts);
/** An OID given as its encoded contents, in hex. */
const oid = (hex: string): Buffer => der(0x06, Buffer.from(hex, "hex"));

/** RFC 5280 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050. */
function time(at: Date): Buffer {
  const digits = at.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  return at.getUTCFullYear() < 2050 ? der(0x17, Buffer.from(`${digits.slice(2)}Z`, "ascii")) : der(0x18, Buffer.from(`${digits}Z`, "ascii"));
}

const ECDSA_WITH_SHA256 = sequence(oid("2a8648ce3d040302"));
const COMMON_NAME = "550403";
const SUBJECT_ALT_NAME = "551d11";

let cached: { key: string; cert: string } | null = null;

/** The PEM key and certificate for a loopback HTTPS server (the same pair for the whole test process). */
export function loopbackCert(): { key: string; cert: string } {
  if (cached) return cached;
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const name = sequence(set(sequence(oid(COMMON_NAME), der(0x0c, Buffer.from("loopback.test", "utf8")))));
  const serial = randomBytes(8);
  // A positive INTEGER in its shortest form: high bit clear, first byte not zero.
  serial[0] = ((serial[0] ?? 0) & 0x7f) | 0x40;
  const altNames = sequence(der(0x82, Buffer.from("localhost", "ascii")), der(0x82, Buffer.from("*.test", "ascii")), der(0x87, Buffer.from([127, 0, 0, 1])));
  const now = Date.now();
  const tbs = sequence(
    der(0xa0, der(0x02, Buffer.from([2]))), // version v3
    der(0x02, serial),
    ECDSA_WITH_SHA256,
    name,
    sequence(time(new Date(now - DAY)), time(new Date(now + 7 * DAY))),
    name,
    publicKey.export({ type: "spki", format: "der" }),
    der(0xa3, sequence(sequence(oid(SUBJECT_ALT_NAME), der(0x04, altNames))))
  );
  const signature = sign("sha256", tbs, privateKey);
  const certificate = sequence(tbs, ECDSA_WITH_SHA256, der(0x03, Buffer.from([0]), signature));
  const base64 = certificate.toString("base64").replace(/.{64}/g, (line) => `${line}\n`);
  cached = {
    key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    cert: `-----BEGIN CERTIFICATE-----\n${base64.trimEnd()}\n-----END CERTIFICATE-----\n`
  };
  return cached;
}
