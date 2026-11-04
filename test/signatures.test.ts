import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { detectTechnologies, extractEvidence, loadSignatureDatabase } from "../src/signatures/index.js";
import { SignatureDatabaseSchema } from "../src/signatures/schema.js";
import raw from "../src/signatures/signatures.json" with { type: "json" };

describe("signature database", () => {
  // The README advertises 450+ signatures, so the floor tracks that claim: losing entries must fail here before the docs become false.
  it("validates against the schema with 450+ unique entries", () => {
    const parsed = SignatureDatabaseSchema.parse(raw);
    assert.ok(parsed.signatures.length >= 450, `expected >= 450 signatures (the README says 450+), got ${parsed.signatures.length}`);
    const ids = new Set(parsed.signatures.map((s) => s.id));
    assert.equal(ids.size, parsed.signatures.length, "duplicate signature ids");
    for (const s of parsed.signatures) assert.ok(s.category in parsed.categories, `unknown category ${s.category} on ${s.id}`);
  });

  it("compiles every pattern", () => {
    const db = loadSignatureDatabase();
    const parsed = SignatureDatabaseSchema.parse(raw);
    for (const source of parsed.signatures) {
      const compiled = db.signatures.find((s) => s.id === source.id);
      assert.ok(compiled, `missing compiled signature ${source.id}`);
      assert.equal(compiled.html.length, source.html.length, `${source.id}: html pattern failed to compile`);
      assert.equal(compiled.scripts.length, source.scripts.length, `${source.id}: script pattern failed to compile`);
      assert.equal(compiled.cookies.length, source.cookies.length, `${source.id}: cookie pattern failed to compile`);
      assert.equal(compiled.meta.length, Object.keys(source.meta).length, `${source.id}: meta pattern failed to compile`);
      // compileSignature drops a non-empty header regex that fails to compile (an empty one is kept as a presence match), so a count mismatch is a broken pattern.
      assert.equal(compiled.headers.length, Object.keys(source.headers).length, `${source.id}: header pattern failed to compile`);
      for (const implied of source.implies)
        assert.ok(
          parsed.signatures.some((s) => s.id === implied),
          `${source.id} implies unknown ${implied}`
        );
    }
  });
});

describe("detectTechnologies", () => {
  const html = `<!DOCTYPE html><html><head>
    <meta name="generator" content="WordPress 6.5.2" />
    <script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>
    <script src="https://static.klaviyo.com/onsite/js/klaviyo.js?company_id=XYZ"></script>
    <script src="/_next/static/chunks/main-abc123.js"></script>
    <script id="__NEXT_DATA__" type="application/json">{}</script>
    <link rel="stylesheet" href="/wp-content/themes/foo/style.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </head><body><div id="__next"></div></body></html>`;

  it("matches html, script, header, cookie and meta evidence and resolves implications", () => {
    const evidence = extractEvidence(html, { server: "cloudflare", "cf-ray": "abc-IAD", "x-powered-by": "Next.js 14.2.1" }, ["__cf_bm=abc; Secure", "wp-settings-1=x"]);
    assert.ok(evidence.scripts.some((s) => s.includes("gtm.js")));
    assert.deepEqual(evidence.meta.generator, ["WordPress 6.5.2"]);
    assert.deepEqual(evidence.cookies, ["__cf_bm", "wp-settings-1"]);
    const detections = detectTechnologies(evidence);
    const byId = new Map(detections.map((d) => [d.id, d]));
    assert.equal(byId.get("wordpress")?.version, "6.5.2");
    assert.equal(byId.get("google-tag-manager")?.category, "tag-manager");
    assert.ok(byId.has("klaviyo"));
    assert.equal(byId.get("nextjs")?.version, "14.2.1");
    assert.equal(byId.get("react")?.implied, true);
    assert.ok(byId.get("cloudflare")?.evidence.some((e) => e.type === "header"));
    assert.equal(byId.get("bootstrap")?.version, "5.3.3");
    assert.equal(byId.get("jsdelivr")?.category, "cdn");
  });

  it("returns nothing for an empty page", () => {
    assert.deepEqual(detectTechnologies(extractEvidence("<html></html>", {}, [])), []);
  });

  it("survives prototype-chain names in response headers", () => {
    const evidence = extractEvidence("<html></html>", { constructor: "x", __proto__: "y", server: "nginx" } as Record<string, string>, []);
    assert.equal(evidence.headers.server, "nginx");
    assert.doesNotThrow(() => detectTechnologies(evidence));
  });
});
