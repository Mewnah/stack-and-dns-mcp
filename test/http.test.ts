import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import net, { type AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import tls from "node:tls";
import { fetchHomepage, type FetchOptions } from "../src/lib/http.js";
import { setLogLevel } from "../src/logger.js";
import { loopbackCert } from "./fixtures/loopback-cert.js";

setLogLevel("silent");

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

/** Plain HTTP loopback server: fetchHomepage's https attempts fail against it and the HTTP downgrade carries the test. */
let plain: http.Server;
let plainOrigin = "";
const plainRoutes = new Map<string, Handler>();

/**
 * Self-signed HTTPS loopback server. The strict attempt fails on its
 * untrusted certificate, so the insecure-TLS retry is the attempt that
 * follows the redirects here (round4-crawler.test.ts drives the strict
 * attempt itself through redirects).
 */
let secure: https.Server;
let secureOrigin = "";
const secureRoutes = new Map<string, Handler>();

function route(routes: Map<string, Handler>): Handler {
  return (req, res) => {
    const handler = routes.get(req.url ?? "/");
    if (handler) handler(req, res);
    else {
      res.writeHead(404);
      res.end("nope");
    }
  };
}

// The suite is offline: a connection to anything but loopback is recorded and
// refused before it leaves the machine (undici connects through these two).
type AnyFn = (...args: unknown[]) => unknown;
const sockets = { net: net as unknown as { connect: AnyFn }, tls: tls as unknown as { connect: AnyFn } };
const originalConnect = { net: sockets.net.connect, tls: sockets.tls.connect };
const offMachine: string[] = [];

function loopbackOnly(original: AnyFn, owner: unknown): AnyFn {
  return (...args: unknown[]) => {
    const host = (args[0] as { host?: string } | null)?.host;
    if (host === undefined || host === "127.0.0.1" || host === "localhost") return original.apply(owner, args);
    offMachine.push(host);
    const socket = new net.Socket();
    process.nextTick(() => socket.destroy(Object.assign(new Error(`connect ECONNREFUSED ${host} (this test suite stays on loopback)`), { code: "ECONNREFUSED" })));
    return socket;
  };
}

before(async () => {
  sockets.net.connect = loopbackOnly(originalConnect.net, net);
  sockets.tls.connect = loopbackOnly(originalConnect.tls, tls);
  plain = http.createServer(route(plainRoutes));
  await new Promise<void>((resolve) => plain.listen(0, "127.0.0.1", resolve));
  plainOrigin = `127.0.0.1:${(plain.address() as AddressInfo).port}`;
  secure = https.createServer(loopbackCert(), route(secureRoutes));
  await new Promise<void>((resolve) => secure.listen(0, "127.0.0.1", resolve));
  secureOrigin = `127.0.0.1:${(secure.address() as AddressInfo).port}`;
});

after(async () => {
  sockets.net.connect = originalConnect.net;
  sockets.tls.connect = originalConnect.tls;
  await new Promise<void>((resolve) => plain.close(() => resolve()));
  secure.closeAllConnections();
  await new Promise<void>((resolve) => secure.close(() => resolve()));
});

const options = (extra: Partial<FetchOptions> = {}): FetchOptions => ({ timeoutMs: 2000, maxBodyBytes: 100000, userAgent: "test", allowPrivate: true, ...extra });

describe("fetchHomepage over plain HTTP (downgrade path)", () => {
  it("refuses a loopback origin when private targets are not allowed", async () => {
    plainRoutes.set("/", (_req, res) => {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
    });
    const result = await fetchHomepage(plainOrigin, options({ allowPrivate: false }));
    assert.equal(result.ok, false);
    assert.equal(result.error?.kind, "private_target");
  });

  it("classifies a client cancellation as aborted and runs no fallback attempts", async () => {
    plainRoutes.set("/", (req) => {
      req.socket.setTimeout(0);
    });
    const controller = new AbortController();
    setTimeout(() => controller.abort("Request cancelled by client"), 100);
    const started = Date.now();
    const result = await fetchHomepage(plainOrigin, options({ signal: controller.signal }));
    assert.equal(result.ok, false);
    assert.equal(result.error?.kind, "aborted");
    assert.equal(result.error?.code, "EABORTED");
    assert.ok(Date.now() - started < 1500, "returned promptly after the abort");
  });

  it("follows a same-host redirect and reports the downgraded final location", async () => {
    plainRoutes.set("/", (_req, res) => {
      res.writeHead(301, { location: `http://${plainOrigin}/home` });
      res.end();
    });
    plainRoutes.set("/home", (_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end('<html><head><meta name="generator" content="WordPress 6.5"></head></html>');
    });
    const result = await fetchHomepage(plainOrigin, options());
    assert.equal(result.ok, true);
    assert.equal(result.httpsDowngraded, true);
    assert.equal(result.protocol, "http");
    assert.equal(result.finalUrl, `http://${plainOrigin}/home`);
    assert.deepEqual(
      result.redirectChain.map((h) => h.location),
      [`http://${plainOrigin}/home`]
    );
    assert.ok(result.html.includes("WordPress"));
  });
});

describe("fetchHomepage over HTTPS (insecure-TLS retry path)", () => {
  it("does not adopt a non-http redirect target as the final location", async () => {
    secureRoutes.set("/", (_req, res) => {
      res.writeHead(302, { location: "javascript:alert(1)" });
      res.end();
    });
    const result = await fetchHomepage(secureOrigin, options());
    assert.equal(result.ok, false);
    assert.equal(result.error?.kind, "redirect");
    assert.equal(result.finalHost, null);
    assert.equal(result.finalUrl, `https://${secureOrigin}/`);
    assert.equal(result.redirectChain.length, 1, "the rejected hop is still listed for transparency");
    assert.equal(result.tlsError?.kind, "tls", "the self-signed certificate triggered the insecure retry");
  });

  it("reports where a failed redirect chain pointed when the target is an http(s) URL", async () => {
    secureRoutes.set("/", (_req, res) => {
      res.writeHead(301, { location: `https://${secureOrigin}/hang` });
      res.end();
    });
    secureRoutes.set("/hang", (req) => {
      req.socket.setTimeout(0);
    });
    const result = await fetchHomepage(secureOrigin, options({ timeoutMs: 800 }));
    assert.equal(result.ok, false);
    assert.equal(result.error?.kind, "timeout");
    assert.equal(result.finalUrl, `https://${secureOrigin}/hang`);
    assert.equal(result.finalHost, "127.0.0.1");
    assert.equal(result.protocol, null);
  });

  it("records a redirect toward a private literal when private targets are explicitly allowed", async () => {
    // The loopback origin is itself a private literal, so the refusal of the
    // redirect target with allowPrivate=false is covered by the direct
    // assertPublicLiteral tests in test/lookup.test.ts; here the hop must be
    // recorded and the target, a loopback port that drops every connection,
    // simply fails. (A link-local target such as 169.254.169.254 would really
    // be requested, and on a cloud runner its metadata service answers.)
    const sink = net.createServer((socket) => socket.destroy());
    await new Promise<void>((resolve) => sink.listen(0, "127.0.0.1", resolve));
    try {
      const target = `http://127.0.0.1:${(sink.address() as AddressInfo).port}/latest/meta-data/`;
      secureRoutes.set("/", (_req, res) => {
        res.writeHead(302, { location: target });
        res.end();
      });
      const result = await fetchHomepage(secureOrigin, options({ allowPrivate: true, timeoutMs: 800 }));
      assert.equal(result.ok, false);
      assert.deepEqual(
        result.redirectChain.map((h) => h.location),
        [target]
      );
      assert.deepEqual(offMachine, [], "nothing was requested off the machine");
    } finally {
      await new Promise<void>((resolve) => sink.close(() => resolve()));
    }
  });
});
