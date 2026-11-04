import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { detectBlock } from "../src/lib/blockDetection.js";

describe("detectBlock", () => {
  it("recognizes Cloudflare managed challenges by header and by HTML", () => {
    const byHeader = detectBlock(403, { "cf-mitigated": "challenge", server: "cloudflare" }, "");
    assert.equal(byHeader.blocked, true);
    assert.equal(byHeader.vendor, "Cloudflare");
    assert.equal(byHeader.challengeType, "javascript");
    const byHtml = detectBlock(
      503,
      { server: "cloudflare" },
      '<html><head><title>Just a moment...</title></head><body>cloudflare <script src="/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1"></script></body></html>'
    );
    assert.equal(byHtml.blocked, true);
    assert.equal(byHtml.vendor, "Cloudflare");
  });

  it("recognizes Akamai, Imperva, DataDome, PerimeterX, AWS WAF and Vercel", () => {
    assert.equal(detectBlock(403, {}, "Access Denied. Reference&#32;#18.abcd").vendor, "Akamai");
    assert.equal(detectBlock(403, {}, "<html><body>Request unsuccessful. Incapsula incident ID: 123</body></html>").vendor, "Imperva");
    assert.equal(detectBlock(403, {}, '<script src="https://ct.captcha-delivery.com/c.js"></script>').vendor, "DataDome");
    assert.equal(detectBlock(403, {}, '<div id="px-captcha"></div>').vendor, "HUMAN (PerimeterX)");
    const waf = detectBlock(405, { "x-amzn-waf-action": "challenge" }, "");
    assert.equal(waf.vendor, "AWS WAF");
    assert.equal(waf.challengeType, "javascript");
    assert.equal(detectBlock(429, { "x-vercel-mitigated": "challenge" }, "").vendor, "Vercel");
  });

  it("treats 429 as rate limiting and short 403 bodies as access denied", () => {
    const limited = detectBlock(429, { server: "nginx" }, "");
    assert.equal(limited.challengeType, "rate_limited");
    const denied = detectBlock(403, {}, "<html><body><h1>Access Denied</h1></body></html>");
    assert.equal(denied.challengeType, "access_denied");
  });

  it("does not flag ordinary pages", () => {
    const ok = detectBlock(200, { server: "cloudflare", "cf-ray": "abc" }, "<html><body>Welcome to our store. Powered by Cloudflare.</body></html>");
    assert.equal(ok.blocked, false);
    const big403 = detectBlock(403, {}, `<html><body>${"custom forbidden page content ".repeat(300)}</body></html>`);
    assert.equal(big403.blocked, false);
  });
});
