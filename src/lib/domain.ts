/**
 * Domain normalization and validation.
 *
 * Accepts the messy inputs agents actually send (full URLs, email addresses,
 * upper-case, trailing slashes, IDN/Unicode names, ports) and reduces them to
 * a validated ASCII hostname. Rejects IP literals and reserved/private names
 * so the inspectors never touch internal infrastructure.
 */

import { isIP } from "node:net";
import { domainToASCII, domainToUnicode } from "node:url";

export interface DomainParseSuccess {
  ok: true;
  input: string;
  domain: string;
  unicode: string;
  registrable: string;
  isSubdomain: boolean;
}

export interface DomainParseFailure {
  ok: false;
  input: string;
  code: "INVALID_DOMAIN" | "PRIVATE_TARGET";
  error: string;
}

export type DomainParseResult = DomainParseSuccess | DomainParseFailure;

const RESERVED_TLDS = new Set([
  "localhost",
  "local",
  "internal",
  "test",
  "invalid",
  "example",
  "onion",
  "home",
  "lan",
  "corp",
  "intranet",
  "private",
  "localdomain",
  "arpa",
  "alt",
  // Service-discovery names that only resolve inside a cluster (Kubernetes, Consul).
  "svc",
  "consul"
]);

/**
 * Compact public-suffix approximation: the multi-label suffixes most likely
 * to appear in B2B prospect lists, plus popular hosted-platform suffixes.
 * Used to derive the organizational domain (DMARC fallback, off-domain
 * redirect reporting) and to group names into zones for the DNS client's
 * fallback trigger. A missing suffix only merges zones, which makes fallback
 * rarer, so completeness is not safety critical.
 */
const MULTI_PART_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "me.uk",
  "net.uk",
  "ltd.uk",
  "plc.uk",
  "sch.uk",
  "nhs.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "asn.au",
  "id.au",
  "co.nz",
  "net.nz",
  "org.nz",
  "ac.nz",
  "govt.nz",
  "school.nz",
  "co.za",
  "org.za",
  "net.za",
  "ac.za",
  "gov.za",
  "web.za",
  "co.jp",
  "ne.jp",
  "or.jp",
  "ac.jp",
  "go.jp",
  "ad.jp",
  "ed.jp",
  "gr.jp",
  "lg.jp",
  "co.kr",
  "or.kr",
  "ne.kr",
  "re.kr",
  "ac.kr",
  "go.kr",
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "edu.br",
  "art.br",
  "eng.br",
  "adv.br",
  "com.mx",
  "org.mx",
  "gob.mx",
  "edu.mx",
  "net.mx",
  "com.ar",
  "org.ar",
  "net.ar",
  "gob.ar",
  "edu.ar",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "edu.cn",
  "ac.cn",
  "com.hk",
  "org.hk",
  "net.hk",
  "edu.hk",
  "gov.hk",
  "com.sg",
  "org.sg",
  "net.sg",
  "edu.sg",
  "gov.sg",
  "com.tw",
  "org.tw",
  "net.tw",
  "edu.tw",
  "gov.tw",
  "com.tr",
  "org.tr",
  "net.tr",
  "edu.tr",
  "gov.tr",
  "co.in",
  "net.in",
  "org.in",
  "ac.in",
  "gov.in",
  "firm.in",
  "gen.in",
  "ind.in",
  "edu.in",
  "res.in",
  "co.il",
  "org.il",
  "net.il",
  "ac.il",
  "gov.il",
  "muni.il",
  "com.my",
  "org.my",
  "net.my",
  "edu.my",
  "gov.my",
  "com.ph",
  "org.ph",
  "net.ph",
  "edu.ph",
  "gov.ph",
  "com.pk",
  "org.pk",
  "net.pk",
  "edu.pk",
  "gov.pk",
  "com.eg",
  "org.eg",
  "net.eg",
  "edu.eg",
  "gov.eg",
  "com.sa",
  "org.sa",
  "net.sa",
  "edu.sa",
  "gov.sa",
  "med.sa",
  "com.ng",
  "org.ng",
  "net.ng",
  "edu.ng",
  "gov.ng",
  "co.ke",
  "or.ke",
  "ne.ke",
  "ac.ke",
  "go.ke",
  "com.co",
  "org.co",
  "net.co",
  "edu.co",
  "gov.co",
  "com.pe",
  "org.pe",
  "net.pe",
  "edu.pe",
  "gob.pe",
  "com.ve",
  "org.ve",
  "net.ve",
  "edu.ve",
  "gob.ve",
  "com.ec",
  "org.ec",
  "net.ec",
  "edu.ec",
  "gob.ec",
  "com.uy",
  "org.uy",
  "net.uy",
  "edu.uy",
  "gub.uy",
  "com.py",
  "org.py",
  "net.py",
  "edu.py",
  "gov.py",
  "com.bo",
  "org.bo",
  "net.bo",
  "edu.bo",
  "gob.bo",
  "co.id",
  "or.id",
  "net.id",
  "ac.id",
  "go.id",
  "web.id",
  "my.id",
  "com.vn",
  "org.vn",
  "net.vn",
  "edu.vn",
  "gov.vn",
  "com.ua",
  "org.ua",
  "net.ua",
  "edu.ua",
  "gov.ua",
  "in.ua",
  "kiev.ua",
  "com.pl",
  "org.pl",
  "net.pl",
  "edu.pl",
  "gov.pl",
  "biz.pl",
  "info.pl",
  "com.ru",
  "org.ru",
  "net.ru",
  "edu.ru",
  "gov.ru",
  "spb.ru",
  "msk.ru",
  "co.th",
  "or.th",
  "in.th",
  "ac.th",
  "go.th",
  "com.bd",
  "org.bd",
  "net.bd",
  "edu.bd",
  "gov.bd",
  "com.np",
  "org.np",
  "net.np",
  "edu.np",
  "gov.np",
  "com.lk",
  "org.lk",
  "net.lk",
  "edu.lk",
  "gov.lk",
  "com.kw",
  "org.kw",
  "net.kw",
  "edu.kw",
  "gov.kw",
  "com.qa",
  "org.qa",
  "net.qa",
  "edu.qa",
  "gov.qa",
  "com.bh",
  "org.bh",
  "net.bh",
  "edu.bh",
  "gov.bh",
  "com.om",
  "org.om",
  "net.om",
  "edu.om",
  "gov.om",
  "com.lb",
  "org.lb",
  "net.lb",
  "edu.lb",
  "gov.lb",
  "com.jo",
  "org.jo",
  "net.jo",
  "edu.jo",
  "gov.jo",
  "com.ly",
  "com.tn",
  "com.dz",
  "co.ma",
  "com.gh",
  "co.tz",
  "co.ug",
  "co.zw",
  "co.bw",
  "co.mz",
  "com.gt",
  "com.sv",
  "com.hn",
  "com.ni",
  "co.cr",
  "com.pa",
  "com.do",
  "com.pr",
  "com.jm",
  "com.tt",
  "co.at",
  "or.at",
  "ac.at",
  "gv.at",
  "com.es",
  "org.es",
  "nom.es",
  "gob.es",
  "edu.es",
  "com.pt",
  "org.pt",
  "edu.pt",
  "gov.pt",
  "com.gr",
  "org.gr",
  "net.gr",
  "edu.gr",
  "gov.gr",
  "com.cy",
  "org.cy",
  "net.cy",
  "ac.cy",
  "gov.cy",
  "com.mt",
  "org.mt",
  "net.mt",
  "edu.mt",
  "gov.mt",
  "com.ee",
  "com.lv",
  "com.lt",
  "com.hr",
  "com.rs",
  "co.rs",
  "com.mk",
  "com.al",
  "com.ba",
  "com.si",
  "com.ro",
  "org.ro",
  "nom.ro",
  "com.bg",
  "com.hu",
  "co.hu",
  "com.sk",
  "com.cz",
  "com.kz",
  "org.kz",
  "com.uz",
  "com.ge",
  "com.am",
  "com.az",
  "com.by",
  "com.md",
  "com.au",
  "com.fj",
  "com.pg",
  "co.ck",
  "com.ws",
  "com.af",
  "com.iq",
  "com.ir",
  "co.ir",
  "com.sy",
  "com.ye",
  "com.et",
  "com.sd",
  "com.so",
  "co.rw",
  "co.bi",
  "com.mw",
  "co.zm",
  "com.na",
  "co.ls",
  "co.sz",
  "com.cm",
  "com.ci",
  "com.sn",
  "com.ml",
  "com.bf",
  "com.ne",
  "com.tg",
  "com.bj",
  "com.gn",
  "com.sl",
  "com.lr",
  "com.gm",
  "com.mr",
  "com.cv",
  "com.gw",
  "com.st",
  "com.ga",
  "com.cg",
  "com.cd",
  "com.ao",
  "com.mg",
  "com.mu",
  "com.sc",
  "com.km",
  "com.re",
  "com.yt",
  "com.mm",
  "com.kh",
  "com.la",
  "com.bn",
  "com.tl",
  "com.mv",
  "com.bt",
  "com.mn",
  "com.kg",
  "com.tj",
  "com.tm",
  "com.pf",
  "com.nc",
  "com.vu",
  "com.sb",
  "com.to",
  "com.nr",
  "com.ki",
  "com.tv",
  "com.fm",
  "com.mh",
  "com.pw",
  "com.as",
  "com.gu",
  "com.mp",
  "com.vi",
  "github.io",
  "gitlab.io",
  "herokuapp.com",
  "vercel.app",
  "netlify.app",
  "pages.dev",
  "workers.dev",
  "web.app",
  "firebaseapp.com",
  "appspot.com",
  "cloudfunctions.net",
  "run.app",
  "myshopify.com",
  "wixsite.com",
  "squarespace.com",
  "webflow.io",
  "framer.app",
  "framer.website",
  "wordpress.com",
  "blogspot.com",
  "tumblr.com",
  "weebly.com",
  "godaddysites.com",
  "cloudfront.net",
  "amazonaws.com",
  "elasticbeanstalk.com",
  "azurewebsites.net",
  "azurestaticapps.net",
  "azureedge.net",
  "cloudapp.net",
  "windows.net",
  "onrender.com",
  "fly.dev",
  "railway.app",
  "ondigitalocean.app",
  "hubspotpagebuilder.com",
  "hs-sites.com",
  "hubspotusercontent-na1.net",
  "readthedocs.io",
  "gitbook.io",
  "notion.site",
  "super.site",
  "carrd.co",
  "bubbleapps.io",
  "glitch.me",
  "repl.co",
  "replit.app",
  "surge.sh",
  "now.sh",
  "zeit.co",
  "stackblitz.io",
  "codesandbox.io",
  "ngrok.io",
  "ngrok.app",
  "ngrok-free.app",
  "loca.lt",
  "trycloudflare.com",
  "pagekite.me",
  "mystrikingly.com",
  "strikingly.com",
  "unbouncepages.com",
  "instapage.com",
  "leadpages.co",
  "clickfunnels.com",
  "kajabi.com",
  "mykajabi.com",
  "teachable.com",
  "thinkific.com",
  "podia.com",
  "gumroad.com",
  "substack.com",
  "beehiiv.com",
  "ghost.io",
  "medium.com",
  "dev.to",
  "hashnode.dev",
  "s3.amazonaws.com",
  "s3-website-us-east-1.amazonaws.com",
  "s3-website-us-west-2.amazonaws.com",
  "elb.amazonaws.com",
  "compute.amazonaws.com",
  "compute-1.amazonaws.com",
  "cloudflare.net",
  "cdn.cloudflare.net",
  "b-cdn.net",
  "kxcdn.com",
  "netdna-cdn.com",
  "stackpathcdn.com",
  "ac.uk",
  "gov.uk",
  "police.uk",
  "mod.uk",
  "parliament.uk",
  "nhs.uk",
  "nic.uk",
  "k12.ca.us",
  "k12.ny.us",
  "k12.tx.us",
  "k12.fl.us",
  "k12.il.us",
  "k12.pa.us",
  "k12.oh.us",
  "k12.mi.us",
  "k12.ga.us",
  "k12.nc.us",
  "cc.ca.us",
  "cc.ny.us",
  "cc.tx.us",
  "lib.ca.us",
  "lib.ny.us",
  "state.ca.us",
  "state.ny.us",
  "state.tx.us",
  "state.fl.us",
  "ci.ca.us",
  "co.ca.us",
  "city.ca.us"
]);

function fail(input: string, code: DomainParseFailure["code"], error: string): DomainParseFailure {
  return { ok: false, input, code, error };
}

/**
 * True when a (pre-IDNA) host has more than 253 code points or a label of
 * more than 63, in linear time. Punycode spends at least one ASCII character
 * per code point, so no valid name exceeds either limit before conversion,
 * whatever its script; the check keeps hostile input away from IDNA, whose
 * cost grows with label length times distinct code points.
 */
function exceedsDnsLength(host: string): boolean {
  let total = 0;
  let label = 0;
  for (const ch of host) {
    if (++total > 253) return true;
    if (ch === "." || ch === "\u3002" || ch === "\uff0e" || ch === "\uff61") label = 0;
    else if (++label > 63) return true;
  }
  return false;
}

/**
 * True when the host the WHATWG URL parser would take from url (whose scheme
 * ends at its first ":") may exceed the DNS limits, in linear time. The host
 * is found the way the parser finds it, since new URL() runs IDNA over it
 * before any length check: tabs and newlines are removed anywhere, special
 * schemes skip any run of "/" and "\" after the scheme, the authority ends
 * at "/", "?", "#" or "\", and the host follows its last "@". A file URL's
 * host has no userinfo or port (IDNA sees all of it, "@" and ":" included),
 * so there the whole authority is bounded. Other schemes get an opaque host,
 * which never goes through IDNA.
 *
 * Node's parser (ada) departs from the spec in one place that matters: once
 * a host contains "[", it looks for the closing "]" past "/", "?" and "\",
 * so IDNA would see the rest of the URL. Only an IP literal may contain "[",
 * and it starts with one; any other host containing it fails anyway, so it
 * is rejected here before the parser runs.
 */
function urlHostExceedsDnsLength(url: string): boolean {
  const clean = url.replace(/[\t\n\r]/g, "");
  const colon = clean.indexOf(":");
  let start = colon + 1;
  while (start < clean.length && (clean[start] === "/" || clean[start] === "\\")) start++;
  let end = start;
  while (end < clean.length && clean[end] !== "/" && clean[end] !== "?" && clean[end] !== "#" && clean[end] !== "\\") end++;
  let host = clean.slice(start, end);
  if (clean.slice(0, colon).toLowerCase() !== "file") {
    host = host.slice(host.lastIndexOf("@") + 1);
    if (host.indexOf("[") > 0) return true;
    // Drop a trailing ":port" (a loop, not a regex, so no input can make it backtrack).
    let digits = host.length;
    while (digits > 0 && host.charCodeAt(digits - 1) >= 48 && host.charCodeAt(digits - 1) <= 57) digits--;
    if (digits > 0 && host[digits - 1] === ":") host = host.slice(0, digits - 1);
  }
  return exceedsDnsLength(host);
}

function extractHostname(raw: string): string | null {
  let value = raw.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value) || value.startsWith("//")) {
    const url = value.startsWith("//") ? `https:${value}` : value;
    if (urlHostExceedsDnsLength(url)) return null;
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  }
  const at = value.lastIndexOf("@");
  if (at !== -1) value = value.slice(at + 1);
  value = value.split(/[/?#\\]/)[0] ?? "";
  value = value.replace(/:\d{1,5}$/, "");
  return value;
}

export function registrableDomain(domain: string): string {
  const labels = domain.toLowerCase().split(".");
  if (labels.length <= 2) return domain.toLowerCase();
  const lastThree = labels.slice(-3).join(".");
  if (labels.length > 3 && MULTI_PART_SUFFIXES.has(lastThree)) return labels.slice(-4).join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

export function stripWww(domain: string): string {
  const lower = domain.toLowerCase();
  if (lower.startsWith("www.") && lower.split(".").length > 2) return lower.slice(4);
  return lower;
}

export function isSubdomainOf(child: string, parent: string): boolean {
  const c = child.toLowerCase();
  const p = parent.toLowerCase();
  return c === p || c.endsWith(`.${p}`);
}

/** Strips leading and trailing dots in linear time (a regex over long runs of dots backtracks quadratically). */
function trimDots(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && value.charCodeAt(start) === 46) start++;
  while (end > start && value.charCodeAt(end - 1) === 46) end--;
  return value.slice(start, end);
}

export function parseDomain(input: unknown, options: { allowPrivate?: boolean } = {}): DomainParseResult {
  const original = typeof input === "string" ? input : String(input ?? "");
  const trimmed = original.trim();
  if (!trimmed) return fail(original, "INVALID_DOMAIN", "Domain is empty. Pass a hostname such as example.com.");
  if (trimmed.length > 2048) return fail(original, "INVALID_DOMAIN", "Input is too long to be a domain or URL.");

  const extracted = extractHostname(trimmed);
  if (extracted === null || extracted.length === 0) {
    return fail(original, "INVALID_DOMAIN", "Could not extract a hostname from the input.");
  }

  let host = trimDots(extracted.toLowerCase());
  // No valid name is longer after IDNA conversion than 253 characters, and a
  // longer one is not worth the IDNA work (bulk lists feed thousands of these).
  if (exceedsDnsLength(host)) return fail(original, "INVALID_DOMAIN", "Hostname exceeds the DNS length limits (253 characters, 63 per label).");
  if (host.startsWith("[") || isIP(host) !== 0) {
    return fail(original, "INVALID_DOMAIN", "IP addresses are not supported. Pass a DNS hostname such as example.com.");
  }

  const ascii = domainToASCII(host);
  if (!ascii) return fail(original, "INVALID_DOMAIN", `"${host}" is not a valid hostname.`);
  host = ascii.toLowerCase();

  if (host.length > 253) return fail(original, "INVALID_DOMAIN", "Hostname exceeds the 253 character DNS limit.");
  const labels = host.split(".");
  if (labels.length < 2) {
    return fail(original, "INVALID_DOMAIN", `"${host}" has no top-level domain. Pass a fully qualified name such as example.com.`);
  }
  for (const label of labels) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) {
      return fail(original, "INVALID_DOMAIN", `Label "${label}" contains invalid characters or hyphen placement.`);
    }
  }
  const tld = labels[labels.length - 1] as string;
  if (!/^(xn--[a-z0-9-]{2,59}|[a-z]{2,63})$/.test(tld)) {
    return fail(original, "INVALID_DOMAIN", `"${tld}" is not a valid top-level domain.`);
  }
  if (!options.allowPrivate && RESERVED_TLDS.has(tld)) {
    return fail(original, "PRIVATE_TARGET", `"${host}" uses a reserved or private top-level domain and cannot be inspected.`);
  }

  const registrable = registrableDomain(host);
  return {
    ok: true,
    input: original,
    domain: host,
    unicode: domainToUnicode(host),
    registrable,
    isSubdomain: host !== registrable
  };
}
