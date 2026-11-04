# stack-and-dns-mcp

**A monetized Model Context Protocol server that inspects any public domain for AI agents.**
Give it a domain and it returns the company's web technology stack, its email deliverability
and DNS health (MX / SPF / DKIM / DMARC / MTA-STS / TLS-RPT / BIMI), and its HTTPS security posture,
all as strictly-typed JSON with 0-100 scores and remediation-ready findings.

Built for Cursor, Claude Desktop, Claude Code, autonomous SDR bots and research agents. Runs
locally over stdio with zero configuration, or as a hosted Streamable HTTP / SSE service that
meters usage per API key and can sell prepaid credits through **HTTP 402 payment challenges**
(Stripe hosted checkout or x402 / Machine Payments Protocol stablecoin payments) or API key
subscriptions through a self-serve signup page.

Every scan is remembered, so it can also tell you what changed: `domain_history` shows when a
company adopted or dropped a tool or weakened its DMARC policy, bulk checks work through whole
lead lists (as MCP tools or a CSV-friendly REST API), watched domains raise alerts, by poll or
signed webhook, when their email posture or stack changes, and `find_domains_using` answers "who
runs Klaviyo?" from a robots.txt-respecting crawl of a domain list you supply.

---

## Contents

- [What the tools return](#what-the-tools-return)
- [Quick start (local, stdio)](#quick-start-local-stdio)
- [Client configuration](#client-configuration)
- [Tool reference](#tool-reference)
- [Hosted mode (HTTP) and monetization](#hosted-mode-http-and-monetization)
- [Configuration reference](#configuration-reference)
- [Defensive design](#defensive-design)
- [Scoring model](#scoring-model)
- [Signature database](#signature-database)
- [Deployment](#deployment)
- [Publishing to MCP marketplaces](#publishing-to-mcp-marketplaces)
- [Development and testing](#development-and-testing)
- [Troubleshooting](#troubleshooting)

---

## What the tools return

| Tool | What it does | Cost |
|------|--------------|------|
| `inspect_tech_stack` | Fetches the homepage (3 s per attempt, at most 6 s with its TLS and `http://` fallbacks, transparent bot UA, redirect and WAF aware) and matches it against **450+ regex signatures** covering CMS, e-commerce, JS frameworks, CDNs, hosting, WAFs, analytics, tag managers, marketing automation, CRM, live chat, payments, ad pixels, consent tools and more. Also inspects the TLS certificate and grades security headers. | 1 credit |
| `verify_email_infrastructure` | Live DNS: MX with provider identification, SPF with recursive include expansion and lookup counting, DKIM discovery across 86 common selectors (key type/length), DMARC with org-domain fallback and report-destination authorization, MTA-STS policy fetch, TLS-RPT, BIMI, disposable-domain detection. Returns severity-sorted risks and a deliverability score. | 1 credit |
| `comprehensive_audit` | Runs both concurrently and aggregates an overall health score (email 40 %, security 35 %, infrastructure maturity 25 %) with merged findings and highlights. | 2 credits |
| `domain_history` | Returns what earlier scans recorded about a domain without scanning again: current and past technologies with first-seen and last-seen dates, the latest email posture, and a dated change log (tool added or removed, DMARC weakened, DKIM key lost, MX provider changed). Available when storage is enabled. | 1 credit |
| `start_bulk_check` + `get_bulk_check`, `list_bulk_checks`, `cancel_bulk_check` | Checks a whole lead list (email, tech or audit per domain) as a background job with paged results and CSV export. Also available as a REST API. | per accepted domain, at the single-domain price; polling is free |
| `watch_domain` + `get_alerts`, `list_watches`, `unwatch_domain` | Re-checks watched domains on a schedule and raises alerts when their email posture or technology stack changes, readable with `get_alerts` or pushed to a signed webhook. | included in plans; prepaid callers pay per scheduled check |
| `find_domains_using` + `list_technologies` | Reverse lookup: which domains run a technology (Shopify, Klaviyo, HubSpot...), from a polite background crawl of an operator-supplied domain list. | 2 credits per page; listing is free |

Every successful result is delivered twice: as pretty-printed JSON in `content[0].text` (for
clients that only read text) and as `structuredContent` validated against a Zod output schema.
Failures never crash the server; they come back as `isError` results with no `structuredContent`,
carrying `{ "error": { "code", "message", "retryable", "details" } }` in `content[0].text` and in
`_meta.error`. Arguments that do not match a tool's input schema (an empty domain, a wrong type, a
missing field) and unknown tool names are rejected by the MCP SDK before the tool runs, with a
plain-text `isError` result (`MCP error -32602: ...`) that has no error object and is not charged;
fix the arguments rather than retrying unchanged.

Example (abbreviated) `comprehensive_audit` highlights for a real store:

```text
Platform: Shopify on Cloudflare (10 technologies detected).
Analytics & tags: Elevar, Google Tag Manager, RudderStack.
Go-to-market stack: Attentive.
Security: B (81/100); TLS valid, HSTS on, CSP off.
Email: Google Workspace; SPF fail; DKIM found; DMARC p=reject (score 92/100, A).
```

---

## Quick start (local, stdio)

Requirements: Node.js 22.13+. Stored scans, the shared credit ledger and every feature built on
them (`domain_history`, bulk checks, monitoring, reverse lookup) use the built-in `node:sqlite`
module. When it cannot be loaded, or the database cannot be opened, the server still starts with
the live inspection tools only and logs why.

```bash
git clone https://github.com/Mewnah/stack-and-dns-mcp.git
cd stack-and-dns-mcp
npm install
npm run build
```

Try it without any MCP client:

```bash
npm run smoke -- shopify.com            # comprehensive audit
npm run smoke -- shopify.com --tech     # tech stack only
npm run smoke -- shopify.com --email    # email infrastructure only
```

Open it in the MCP Inspector:

```bash
npm run inspector
```

Or run the server directly (stdio is the default transport):

```bash
node dist/index.js
```

Logs always go to **stderr** as JSON lines; stdout is reserved for the MCP protocol.

---

## Client configuration

The usage file and the database default to `./data/usage.json` and `./data/stackdns.db`, relative
to the directory the server is started in. MCP clients usually start servers somewhere else (an
application folder, `/`, whichever project is open), so the examples below set both to absolute
paths. Otherwise the data lands in a different place per client, or storage is switched off with
only a log warning when that directory is not writable.

### Cursor

A project-level file is included at [`.cursor/mcp.json`](.cursor/mcp.json). Cursor runs
project servers from the workspace root, so the relative paths work after `npm run build`.
For a global install use absolute paths, with a checkout or with the published package:

```json
{
  "mcpServers": {
    "stack-and-dns": {
      "command": "node",
      "args": ["/absolute/path/to/stack-and-dns-mcp/dist/index.js"],
      "env": {
        "STACKDNS_LOG_LEVEL": "warn",
        "STACKDNS_USAGE_FILE": "/absolute/path/to/stack-and-dns-mcp/data/usage.json",
        "STACKDNS_DB_FILE": "/absolute/path/to/stack-and-dns-mcp/data/stackdns.db"
      }
    }
  }
}
```

```json
{
  "mcpServers": {
    "stack-and-dns": {
      "command": "npx",
      "args": ["-y", "stack-and-dns-mcp"],
      "env": {
        "STACKDNS_LOG_LEVEL": "warn",
        "STACKDNS_USAGE_FILE": "/absolute/path/to/stack-and-dns-data/usage.json",
        "STACKDNS_DB_FILE": "/absolute/path/to/stack-and-dns-data/stackdns.db"
      }
    }
  }
}
```

### Claude Desktop

Edit `claude_desktop_config.json`
(`%APPDATA%\Claude\claude_desktop_config.json` on Windows,
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS).
A Windows example is in [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json).

```json
{
  "mcpServers": {
    "stack-and-dns": {
      "command": "node",
      "args": ["D:\\Projects\\MCP\\stack-and-dns-mcp\\dist\\index.js"],
      "env": {
        "STACKDNS_LOG_LEVEL": "warn",
        "STACKDNS_USAGE_FILE": "D:\\Projects\\MCP\\stack-and-dns-mcp\\data\\usage.json",
        "STACKDNS_DB_FILE": "D:\\Projects\\MCP\\stack-and-dns-mcp\\data\\stackdns.db"
      }
    }
  }
}
```

macOS / Linux:

```json
{
  "mcpServers": {
    "stack-and-dns": {
      "command": "node",
      "args": ["/Users/you/stack-and-dns-mcp/dist/index.js"],
      "env": {
        "STACKDNS_LOG_LEVEL": "warn",
        "STACKDNS_USAGE_FILE": "/Users/you/stack-and-dns-mcp/data/usage.json",
        "STACKDNS_DB_FILE": "/Users/you/stack-and-dns-mcp/data/stackdns.db"
      }
    }
  }
}
```

Restart Claude Desktop; the tools appear under the tools icon: the three inspection tools always,
plus `domain_history`, the four bulk-check tools and the four monitoring tools when storage is
available (12 in all), and `find_domains_using` / `list_technologies` when a crawl seed file is set.

### Claude Code

```bash
claude mcp add stack-and-dns \
  -e STACKDNS_USAGE_FILE=/absolute/path/to/stack-and-dns-mcp/data/usage.json \
  -e STACKDNS_DB_FILE=/absolute/path/to/stack-and-dns-mcp/data/stackdns.db \
  -- node /absolute/path/to/stack-and-dns-mcp/dist/index.js
```

Remote deployment:

```bash
claude mcp add --transport http stack-and-dns https://mcp.example.com/mcp --header "Authorization: Bearer sdm_live_..."
```

### Metering a local stdio install with a customer key

A stdio server never contacts a hosted deployment; to use a hosted server's key, connect over HTTP
as in the remote example above. `STACKDNS_API_KEY` only selects one of the keys configured in the
same process (`STACKDNS_API_KEYS` or `STACKDNS_API_KEYS_FILE` in the same `env` block), so a local
install can be metered and rate-limited under that key's plan. Without such keys the variable is
ignored (the server logs a warning at startup) and the server runs in open `local` mode, unless
`STACKDNS_REQUIRE_AUTH=true`, in which case every tool call answers `UNAUTHORIZED`. With keys
configured but `STACKDNS_API_KEY` unset, or set to a key that matches none (that case logs a
warning), the process runs as an anonymous `free` caller: the other tools work within the `free` plan's quota, and the bulk-check and
monitoring tools answer `UNAUTHORIZED`.

---

## Tool reference

The tools that take a `domain` (the three inspection tools, `domain_history` and `watch_domain`)
accept it as a bare hostname (`example.com`), a URL (`https://www.example.com/pricing`) or an
email address (`jane@example.com`); `start_bulk_check` takes a list of the same forms. Scheme,
path, port, query and a leading `www.` (for email checks) are stripped; IDN names are punycoded.
An empty or whitespace-only `domain` fails the input schema (see above), not `INVALID_DOMAIN`.

### `inspect_tech_stack`

```json
{ "domain": "allbirds.com", "includeRawHeaders": false, "includeEvidence": true }
```

Key output fields:

| Field | Description |
|-------|-------------|
| `fetch` | Final URL, status, redirect chain, protocol, timings, HTTPS downgrade / TLS error flags, structured `error` when unreachable |
| `blocked` | `{ blocked, vendor, challengeType, reason }` for Cloudflare, Akamai, Imperva, DataDome, HUMAN, AWS WAF, Kasada, Vercel, Sucuri, F5 challenges |
| `partial` | `true` when the fetch failed, was blocked, or the body was truncated |
| `technologies[]` | `{ id, name, category, categoryLabel, website, confidence, version, implied, evidence[] }` |
| `categories` | Category id to detected names |
| `summary` | `cms`, `ecommerce`, `framework`, `cdn`, `hosting`, `webServer`, `tagManager`, `analytics[]`, `marketingAutomation[]`, `crm[]`, `payments[]`, `liveChat[]`, `advertising[]`, `waf[]` |
| `security` | `score`, `grade`, `breakdown`, full `tls` inspection, `headers` report (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/CORP, cookie flags, version leaks), `findings[]` |
| `warnings[]` | Human-readable caveats (blocked, truncated, downgraded, redirected off-domain) |
| `billing` | `{ principal, plan, creditsCharged, creditsRemaining, requestsRemainingThisMinute, requestsRemainingToday }`, on every tool's result. `creditsCharged` is the prepaid credits this call itself charged: 0 for plan keys, which spend daily quota instead, and 0 for `start_bulk_check`, whose up-front charge is in `job.creditsCharged` / `job.quotaUnitsCharged` (`creditsRemaining` already reflects it). `requestsRemainingToday` is the daily quota left after the call, including the units a bulk submission charges (one per accepted domain). |

### `verify_email_infrastructure`

```json
{ "domain": "example.com", "dkimSelectors": ["mycustomselector"], "checkMtaSts": true }
```

| Field | Description |
|-------|-------------|
| `mx` | Sorted exchanges with resolved addresses, provider (Google Workspace, Microsoft 365, Proofpoint, Mimecast, Zoho, and 60+ more), Null-MX and implicit-A detection |
| `spf` | Raw record, parsed mechanisms/modifiers, terminal `all` policy (inherited through `redirect=`), recursive `includeChain`, DNS lookup count vs the 10-lookup limit, void lookups, detected sending platforms. `allPolicy` also reads `none` when the policy sits behind a `redirect=` target whose lookup failed (`allQualifier` null, `redirect` set, `SPF_DNS_ERROR` in `risks`): the policy is then unknown, not absent |
| `dkim` | Every probed selector with key type, bit length, testing/revoked flags and provider hints |
| `dmarc` | Policy, subdomain policy, effective policy, pct, alignment, `rua`/`ruf` destinations with external-authorization checks, enforcement level. `inheritedFromOrganizationalDomain: true` together with `DMARC_DNS_ERROR` in `risks` means a subdomain's own `_dmarc` lookup failed: the record and policies shown are the organizational domain's, and the subdomain's own policy is unknown (scored like `p=none`) |
| `mtaSts`, `tlsRpt`, `bimi` | Transport policy records; the MTA-STS policy file is fetched and checked against the MX hosts |
| `disposable` | Match against a curated list of 469 throwaway-mail providers |
| `risks[]` | Severity-sorted `{ severity, code, message, recommendation }` |
| `score`, `grade`, `scoreBreakdown` | 0-100 deliverability score with per-component points |
| `summary` | One-line human summary. A policy that a failed lookup left unknown reads unknown (`SPF policy unknown (redirect=<target> lookup failed)`, `DMARC unknown (own _dmarc lookup failed; organizational p=<x>)`), and the risk counts in it then leave out the organizational record's DMARC findings (`riskCounts` keeps every finding) |

### `comprehensive_audit`

```json
{ "domain": "hubspot.com", "dkimSelectors": [], "includeRawHeaders": false, "includeEvidence": false }
```

Returns `scores` (`overall`, `grade`, `email`, `security`, `infrastructure`, weights and the
infrastructure breakdown), the full `techStack` and `email` results (or `techStackError` /
`emailError` if one side failed), merged `findings`, `findingCounts`, agent-friendly
`highlights[]` and a `summary` sentence. The `summary` sentence's counts leave out the
organizational record's DMARC findings when a subdomain's own `_dmarc` lookup failed;
`findingCounts` counts every finding.

### `domain_history`

```json
{ "domain": "example.com", "changesLimit": 50 }
```

Reads stored scans only; it never contacts the domain. Every completed scan (a call to one of the
three inspection tools, a bulk-check item, a scheduled monitor check or a reverse-lookup crawl) is recorded in the database
named by `STACKDNS_DB_FILE`, keyed by the site with any leading `www.` removed. A call that was
cancelled or hit its deadline is not recorded, because its lookups may have been cut short. Stored
scans never record which caller requested them.

| Field | Contents |
|-------|----------|
| `known` | `false` when the domain has never been scanned here; the other fields are then empty |
| `technologies[]` | `{ id, name, category, version, implied, active, firstSeen, lastSeen, removedAt }` |
| `email` | Latest posture: score, grade, MX provider, SPF and DMARC policy, live DKIM selectors, MTA-STS mode, critical and high risk codes |
| `changes[]` | Newest first: `{ kind, change, subject, oldValue, newValue, severity, at }`, where `change` is one of `tech_added`, `tech_removed`, `mx_provider`, `mx_added`, `mx_removed`, `null_mx`, `spf_added`, `spf_removed`, `spf_policy`, `spf_broken`, `spf_fixed`, `dmarc_added`, `dmarc_removed`, `dmarc_policy`, `dkim_added`, `dkim_lost`, `mta_sts_mode`, `risk_new`, `risk_resolved`, `score_drop`, `score_rise` |
| `recentScans[]` | The last 20 scans with source (`call`, `bulk`, `monitor` or `crawl`), time, success flag, score and grade |

The first usable scan of a domain is a baseline and records no changes. A technology or DKIM
selector must be missing from two consecutive clean scans before it is reported as removed, so a
lazily loaded tag does not flap. Website scans that were blocked or failed are kept for the record
but never change the stored state.

Email components are tracked separately: the MX records, whether the exchanges resolve, the SPF
record, the SPF include tree, DMARC, MTA-STS, TLS-RPT/BIMI, and each DKIM selector. Each one updates,
and is compared, only when its own lookups answered:

- A component whose lookup failed (SERVFAIL, a timeout, a policy host that answered 5xx or 408, a
  bot challenge) keeps its last known value and reports no change. The components that did answer
  in the same scan are still compared, so a failed include never hides a `+all` in the domain's own
  record.
- A definitive answer is a real change: an MTA-STS policy that returns 404, a policy host that does
  not exist (confirmed with our own resolver), or an invalid certificate.
- A failure that persists for three scans spanning at least a day is accepted as the answer,
  because receivers see the same failure: exchanges that never resolve become
  `MX_ALL_UNRESOLVABLE`, a policy host that never answers removes the MTA-STS mode. Nothing stays
  frozen forever. The streak only grows while the same lookup keeps failing, so a single timeout of
  something else is still held.
- The score only moves when every lookup answered or its failure was accepted as persistent; only
  a scan whose lookups all answered is stored with `ok: true`. While a subdomain's own `_dmarc`
  lookup fails, the stored score keeps the subdomain's last known DMARC points (the live score
  scores the unknown policy like `p=none`), so a timeout neither raises nor lowers it.
- DKIM risks and the score are compared only between scans that probed the same selectors. A key
  under a custom selector that one call passed and a bulk scan did not probe never reads as added
  or lost. Every email scan (calls, bulk items, scheduled checks) also probes every selector
  already known for the domain.
- Records are evaluated in a fixed order, so a domain that publishes two SPF or DMARC records does
  not flip policy between scans because resolvers return them in a different order.
- A subdomain whose own `_dmarc` lookup fails is never credited with the organizational domain's
  policy: the policy reads `unknown` (the live score scores it like `p=none`), and the
  organizational record's findings are not taken as the subdomain's (the one-line `summary` does
  not count them either; `riskCounts` still does). The subdomain's own DMARC stays in `unverified`
  until its own lookup has answered once, and that first answer is a baseline, not a change. A
  subdomain that simply has no record of its own still inherits the organizational policy. When
  the lookup of an SPF `redirect=` target fails, the stored and bulk policy reads `unknown` too,
  not `none`, and the findings that describe the terminal `all` (`SPF_PASS_ALL`,
  `SPF_NEUTRAL_ALL`, `SPF_SOFTFAIL_ALL`) keep their last known state. The live
  `verify_email_infrastructure` field `spf.allPolicy` still reads `none` in that case (its enum has
  no `unknown`); `SPF_DNS_ERROR`, the score note and the summary
  (`SPF policy unknown (redirect=<target> lookup failed)`) flag it.
- SPF whose `redirect=` chain has never answered whole (the target or a later `redirect=` hop
  failed) stays in `unverified` (with `spfLookups`) only until that failure is accepted as
  persistent. The domain's own record did answer, so from then on it is compared as usual while
  its policy reads `unknown`: a second record raises `SPF_MULTIPLE_RECORDS`; deleting the record,
  or an accepted failure of its own TXT lookup, is `spf_removed`; and a record that stops handing
  its policy to that target (another `redirect=` target, or an `all` of its own, which overrides
  `redirect=`) is compared like any other change. A deletion, an accepted lookup failure and a
  record that stops delegating each end the wait for the target, so whatever follows is compared
  as usual too. A second record ends it only when the record evaluated (the first in sorted order)
  no longer delegates to the target. Only what the `redirect=` chain holds was never read whole.
  While the record still delegates to the target, the first scan in which the whole chain answers
  is the baseline of the terminal policy and the findings that describe it (no `spf_policy`,
  `risk_new` or `risk_resolved` for them). The first such scan in which `spfLookups` is
  established too (the include tree answers, or an include's failure has been accepted) is the
  include tree's baseline: no `spf_broken`, `spf_fixed`, `risk_new` or `risk_resolved` for
  validity, lookup counts or void lookups (`SPF_VOID_LOOKUPS`, `SPF_TOO_MANY_LOOKUPS`,
  `SPF_CIRCULAR_INCLUDE`). That is a later scan than the policy's when an include lookup failed in
  the policy's scan, and it still reports a policy change made in between. Until the whole chain
  answers, the first scan in which the target answered but a later hop's failure was accepted is
  a baseline for the tree read so far (if the target already answered in the scan that took SPF
  out of `unverified`, that scan was this baseline); later such scans are compared with it. Each
  of these baselines covers the score too: no `score_drop` or `score_rise` in its scan, even for a
  score change another component caused. Findings of the domain's own record (such as
  `SPF_MULTIPLE_RECORDS` or `SPF_SYNTAX_ERROR`) and changes to other components are still
  reported in that scan.

Weakened policies (DMARC `reject` to `none`, SPF `-all` to `~all`) are `high`, and an MTA-STS
downgrade is `medium`; strengthened ones are `info`. An `unknown` policy ranks with `none`:
`reject` or `-all` becoming `unknown` is `high`, and `none` becoming `unknown` is `info`. A policy
read again after an `unknown` stretch is ranked against the policy last actually read before it,
not against `unknown`: the same policy coming back (even `+all` or a malformed DMARC record) is
`info`, while `quarantine` coming back as `none`, or `-all` as `+all`, is `high`. A move away from
`unknown` with no policy read before it is `info`. In `email`, `score` is `null` until a scan in
which every lookup answered or its failure was accepted as persistent. `unverified` lists
components not yet established: no lookup has answered them and their failure has not been
accepted as persistent (DMARC and SPF behind `redirect=` follow the rules above). `lookupsFailing`
lists those whose latest lookups failed (their fields are the last known values, or the current
reading once the failure was accepted as persistent), so an empty `unverified` does not mean every
lookup answered: an accepted failure is listed in `lookupsFailing`. States stored by earlier
versions are re-baselined silently on their next scan, with no change records: an organizational
DMARC policy or its findings stored for a subdomain whose own lookup failure had been accepted, an
SPF policy stored as `none` behind an accepted failed `redirect=` target, and a stored score from
before SPF void-lookup and circular-include permerrors cost points, when the findings stored with
that score and the scan that next rewrites it both carry such a permerror (a permerror that first
appears after the upgrade is reported as a `score_drop` as usual). When a scan sets a DMARC or SPF
baseline but cannot rewrite the score because another lookup failed, the next scan that rewrites
the score re-baselines it silently.

### Bulk checks: `start_bulk_check`, `get_bulk_check`, `list_bulk_checks`, `cancel_bulk_check`

```json
{ "check": "email", "domains": ["acme.com", "https://www.globex.com/about", "jane@initech.com"] }
```

`check` is `email` (`verify_email_infrastructure`), `tech` (`inspect_tech_stack`) or `audit`
(`comprehensive_audit`). The job is queued at once and worked through in the background by a
small pool shared fairly by every job, so one large list cannot starve a small one; jobs survive
restarts. `start_bulk_check` returns the job id, the inputs that were skipped (invalid, private,
or a duplicate of an earlier site) and what was charged. Poll `get_bulk_check` with the job id: it
returns status, per-status counts and one page of results (`offset`, `limit` up to 500,
optional `status` filter such as `failed`). Each result is a compact summary: score, grade, MX
provider, SPF and DMARC policy, DKIM found and high risks for `email`; reachability, HTTP status,
security grade, CMS, e-commerce, CDN and technology names for `tech`; the four scores and top
highlights for `audit`. In `email` summaries the SPF and DMARC policy can also read `missing` (no
record) or `unknown` (the lookup failed, a `redirect=` target's lookup failed, or a subdomain's own
`_dmarc` lookup failed), the DMARC policy `invalid` (a record without a valid policy), and the MX
provider `unknown` (the MX lookup failed) or `null MX (no mail)`. Jobs are private to the caller
that submitted them, so bulk checks (and monitoring) need an identified caller (an API key, a
prepaid session, or a stdio server's own local identity): anonymous callers on a server with
`STACKDNS_REQUIRE_AUTH=false` share an address-based identity and are refused.

Billing happens once, when the job is accepted: prepaid callers pay the single-domain price per
accepted domain (email 1, tech 1, audit 2 credits), and plan keys spend one unit of their daily
quota per domain, all or nothing. Items that fail for a retryable reason (a timeout, a resolver
outage) and items cancelled before they ran are refunded when the job finishes. A definitive
answer such as `DOMAIN_NOT_FOUND` is a completed check and is charged. The polling, listing and
cancelling tools are free and never touch the daily quota. Limits: `STACKDNS_BULK_MAX_DOMAINS`
per job (default 1000) and `STACKDNS_BULK_MAX_ACTIVE_JOBS` unfinished jobs per caller (default 3).
A list may carry up to twice `STACKDNS_BULK_MAX_DOMAINS` raw entries; a longer list, or one with
more distinct domains than the maximum, is refused with `LIMIT_EXCEEDED` (`details.maxDomains`),
over MCP as over REST. Only a list over max(50000, 2 x `STACKDNS_BULK_MAX_DOMAINS`) entries fails
`start_bulk_check`'s input schema first, which gives the plain-text `-32602` result. A list with more
invalid or duplicate entries than `max(100, accepted domains)` is refused with `INVALID_ARGUMENT`,
since skipped entries are stored too. A prepaid session whose balance a job spent to zero can still read
and cancel its jobs, even when its client keeps re-sending the payment header it paid with; only
paid calls and new job submissions (`POST /v1/jobs` or `start_bulk_check`) answer with a new
payment challenge.

### Monitoring: `watch_domain`, `get_alerts`, `list_watches`, `unwatch_domain`

```json
{ "domain": "acme.com", "checks": ["email", "tech"], "webhookUrl": "https://hooks.example.com/stackdns" }
```

A watched domain is re-checked every `STACKDNS_MONITOR_INTERVAL_HOURS` (default 24), once per
domain however many callers watch it. A check that fails for a retryable reason (a timeout, a
resolver outage) is retried after 30 minutes (or the interval, if shorter) and its prepaid charge
is refunded; a definitive answer such as NXDOMAIN is charged, raises one `domain_not_found` alert
and waits a full interval. Every change the scan store records (see
`domain_history`) becomes an alert for each watcher: DMARC or SPF weakened, a DKIM key lost, the
MX provider changed, a technology added or removed, a score drop, or the domain disappearing from
DNS. Changes found by any scan reach watchers, including a direct call or a bulk job. A new watch
only hears about changes from then on. Unwatching and watching again keeps the existing schedule,
so it never forces an early check.

`get_alerts` returns unread alerts oldest first and marks them read (`markRead: false` to peek,
`sinceId` and `nextSinceId` to page). With a `webhookUrl` (https only, a fully qualified public host
name or public address, no redirects followed) each batch is also POSTed as JSON:

```json
{ "type": "domain.changes", "watchId": "watch_...", "domain": "acme.com", "sentAt": "...",
  "alerts": [{ "id": 42, "kind": "email", "change": "dmarc_policy", "subject": "dmarc", "oldValue": "reject", "newValue": "none", "severity": "high", "at": "..." }] }
```

The request carries `x-stackdns-signature: t=<unix seconds>,v1=<hex>`, where `v1` is the
HMAC-SHA256 of `<t>.<raw body>` keyed with the `webhookSecret` returned once when the watch is
created. The timestamp is taken when the request is sent, so verify it and reject timestamps
older than a few minutes. A delivery that fails is retried after 1 minute, 5 minutes, 30 minutes,
2 hours and 12 hours, then marked failed; the alert stays readable through `get_alerts` either
way, with a short reason ("timed out", "DNS lookup failed", "HTTP 503"). Deliveries run beside the
scheduled checks, at most one request at a time per account, so a slow endpoint delays only its
own owner's alerts, and accounts take turns watch by watch within each delivery round, so neither
one account's backlog nor a few slow receivers hold up everyone else's webhooks.

Plans include a number of watched domains (`free` 5, `pro` 100, `enterprise` 2000, `payg` 500,
override with `STACKDNS_MONITOR_WATCH_LIMITS_JSON`). Prepaid callers pay
`STACKDNS_MONITOR_CREDITS_PER_CHECK` (default 1) per scheduled check. When the balance runs out
the watch pauses with a `watch_paused` alert, and it resumes by itself once the balance covers a
check again. Self-serve accounts' watches follow the subscription: they pause (`plan_inactive`)
while it is cancelled or unpaid, the newest beyond a downgraded plan's limit pause
(`over_plan_limit`), and they resume when the plan allows them again. When the subscription is
deleted for good (including after its key was already suspended for failed payments), its
watches are removed, up to 200 per round across all such accounts, since no key can manage them
any more; until then they stay paused and their pending webhook deliveries are cancelled, even a
delivery that is in flight at that moment. Watching, listing and reading alerts are free.
Monitoring needs an identified caller (an API key, a prepaid session, or a stdio server's own
local identity); watches that anonymous callers created on earlier versions are removed by the
schema upgrade.

### Reverse lookup: `find_domains_using`, `list_technologies`

```json
{ "technology": "Klaviyo", "activeOnly": true, "seenWithinDays": 90, "limit": 50 }
```

Returns domains that run a technology, most recently seen first, with the detected version and
first-seen and last-seen dates, plus `nextCursor` for the next page. `technology` is a signature
id or name; an ambiguous name returns `INVALID_ARGUMENT` with the matching candidates in
`details.candidates`. `list_technologies` browses the catalogue (filter by `query` or `category`)
with how many domains currently use each technology.

The searchable universe is the crawl list, not the internet. An operator points
`STACKDNS_CRAWL_SEED_FILE` at a file of domains (one per line, or the first column of a CSV,
re-read when it changes), and a background crawler works through it at
`STACKDNS_CRAWL_RATE_PER_MINUTE` (default 20), re-visiting each domain every
`STACKDNS_CRAWL_REFRESH_DAYS` (default 30). For each domain it:

- reads `https://<domain>/robots.txt` first and skips the site when the group for our user agent
  (`StackAndDnsBot`, also matched when a group names it with a version such as
  `StackAndDnsBot/1.0`), or the `*` group when no group names it, does not allow `/` (RFC 9309:
  a group naming us overrides `*`, the rule with the most octets wins, rules and paths are
  compared in one percent-encoded form, so `Disallow: /über/` also covers `/%C3%BCber/`, and a
  literal `*` or `$` is named by its escape, `%2A` or `%24`);
- fetches only the homepage, with the same transparent User-Agent, 3-second per-attempt deadline
  (6 s at most) and SSRF guard as `inspect_tech_stack`, and checks every URL the fetch requests (a
  redirect, the `http://` fallback) against the robots.txt of that URL's origin first; each
  origin's file is downloaded once per crawl, and the time spent reading it counts neither against
  the homepage's deadline nor against the time left for the insecure-TLS retry and the `http://`
  fallback; when HTTPS fails and robots.txt refuses the `http://` fallback, the domain is recorded
  as unreachable and its last error names both the HTTPS failure (its first 300 characters) and
  the refusal;
- records the result like any other scan, so crawled domains also build up `domain_history` and
  can raise monitoring alerts;
- treats a robots.txt that answers 5xx or 429, or cannot be fetched, as "not now": the site is
  skipped, keeps its data and is retried on the failure schedule (after 1 hour, doubling);
- waits a full refresh before retrying a domain that does not exist, and removes a site's data
  from the reverse lookup (and from `universe.scanned`) when its robots.txt opts out or the
  domain stops existing.

The reverse lookup answers only from what the crawler itself observed, for domains on the crawl
list. Customers' calls, bulk jobs and monitor scans never appear there (not even their timing for
a crawl-list domain), so the tool cannot reveal anyone's prospect list. A changed seed file is
applied once it has stopped changing for one round, so a file being rewritten is never read half
written, and in small batches with pauses between them, so even a list of millions of domains
neither stalls the server nor holds up other processes' writes to the database. The list is parsed
into a private in-memory SQLite database and compared with the crawl targets there. That database
is attached only while the sync runs (about 200 MB for 5 million domains) and freed when it ends;
the list is never held in the JavaScript heap. At most `STACKDNS_CRAWL_MAX_TARGETS` distinct valid
domains are taken from the file, in file order. `universe.domains` and `universe.scanned` in each
answer say how large the searchable set is; `GET /healthz` reports crawl progress. Without a seed
file the two tools are not offered.

### Error codes

| Code | Retry? | Meaning |
|------|--------|---------|
| `INVALID_DOMAIN` | no | Input is not a resolvable hostname (IP literal, single label, bad characters) |
| `PRIVATE_TARGET` | no | Reserved TLD or the host resolves to loopback / private / link-local / metadata space |
| `DOMAIN_NOT_FOUND` | no | NXDOMAIN |
| `NETWORK_ERROR` | yes | DNS resolution failed at the resolver level |
| `RATE_LIMITED` | yes | Plan quota exceeded; `details.retryAfterMs` says when (a concurrency rejection carries `details.maxConcurrent` instead; retry when an in-flight call finishes) |
| `INSUFFICIENT_CREDITS` | after payment | Prepaid balance exhausted |
| `UNAUTHORIZED` | no | Server requires an API key, or a bulk-check or monitoring tool was called anonymously (they need an identified caller: an API key, a prepaid session, or a stdio server's own local identity) |
| `TOOL_TIMEOUT` | yes | Tool exceeded `STACKDNS_TOOL_TIMEOUT_MS` |
| `CANCELLED` | yes | The client cancelled the request before it completed; nothing was charged |
| `INVALID_ARGUMENT` | no | A bulk, monitoring, reverse-lookup or REST argument is malformed (no valid domains, unknown check, bad webhook URL, an unknown or ambiguous technology with `details.candidates`, a cursor not returned by a previous call, an unknown `?status`) |
| `NOT_FOUND` | no | No bulk check with that id exists for this caller |
| `LIMIT_EXCEEDED` | when `retryable` | A plan or server limit was reached: too many domains in one job or too many watches (no), or too many unfinished jobs (yes, once one finishes) |
| `INTERNAL_ERROR` | yes | Unexpected failure (logged server-side) |

These codes come from the tools themselves. Arguments that fail a tool's input schema (an empty or
whitespace-only domain included) never reach it: the SDK answers with a plain-text
`MCP error -32602: ...` result that carries no code, so such input never yields `INVALID_DOMAIN`.

Payment redemption over HTTP answers `503 payment_recording_failed` when a payment verified (or
settled) but could not be recorded yet; retrying the same credential is safe and never pays twice.
For x402 the 503 carries `X-Session-Token` (and `sessionToken` in the body) for the principal the
credits will land on: keep it. Any process sharing the database finishes the recording in the
background, and until then that token is answered `503`, never a new payment demand. A retry of
the same `X-PAYMENT` header completes the recording too, but it never hands out a token again: a
settled authorization is public on-chain, so presenting it proves nothing about who paid. The
503's principal gets nothing when the credits go to another presentation of the same
authorization (with or without `from`) instead: one that settled earlier, even one first answered
unconfirmed, or one a sibling process recorded first because it could not see this settlement
(see [Any Node host](#any-node-host-flyio-render-railway-ecs-a-vm)). A retry of that 503's header
then answers `409 payment_already_redeemed`.

When the facilitator does not confirm a settlement (a timeout or a 5xx on `/settle`, or success
without a transaction id), the answer is `502 x402_settlement_unconfirmed`, again with the session
token (left out only when the server could not store the unconfirmed state; the operator then
issues it with `npm run settlements -- session <principalId>`, the principal being in the server's
log line), never a new 402: the transfer may have gone through, so do not pay again. A prepaid
session that can serve the request is served from its balance instead, with
`X-Payment-Status: x402_settlement_unconfirmed`. That means a session with credits left, or any
session on a request that spends nothing, such as reading or cancelling jobs. The 502 is only for
requests nothing else can serve. The server keeps that state as long as it remembers redeemed
payments (400 days), across restarts and sibling processes; with `STACKDNS_DB_FILE=none` it is kept
in the usage file. A retry of the same header settles the payment if the facilitator shows the
authorization unspent, and otherwise answers "unconfirmed", never `x402_expired`. The facilitator
is asked again at most once a minute per payment, whichever process gets the retry; retries in
between are answered from the stored state. For 24 hours after the payment's last update (a
re-check counts), the session it would credit answers a spending request its balance cannot cover
with that 502 rather than a payment demand. That holds whether or not its client re-attaches the
payment header. After that the session may buy again: a spending request it cannot cover gets the
`402 credits_exhausted` payment demand, and when the unconfirmed header is attached the 402 also
carries `X-Payment-Status: x402_settlement_unconfirmed`. The header sent without a session keeps
answering 502. Contact the operator with the header to reconcile. The server logs the payer,
amount and target principal, and the operator resolves the payment with `npm run settlements` (see
[Reconciling x402 settlements](#reconciling-x402-settlements)).

A retry of a payment that is already recorded answers `409 payment_already_redeemed`, even when its
stored settlement state could not be removed at the time.

If the answer to a 502 or 503 is lost (for example a client timeout), retrying the payment without
a session does not return the token: a settled authorization is public on-chain, so presenting it
proves nothing. The operator can issue the session with
`npm run settlements -- session <principalId>`.

One narrow case remains. Suppose the database fails both the 'settled' marker write and the
recording. The 503 still goes out with the session, and the process then stops before its
background retry publishes the marker. A later presenter of the same (public) payment header could
then be handed that session, but only if the facilitator also settles an already-spent
authorization again, or the transfer is still pending. All three must coincide. The error log line
`settled x402 payment answered with its session, but its 'settled' marker could not be written`
flags such a payment for manual reconciliation.

An unreachable or blocked homepage is **not** an error: the tool returns `fetch.ok=false` /
`blocked.blocked=true` with the TLS and DNS data it could still gather.

---

## Hosted mode (HTTP) and monetization

```bash
node dist/index.js --http --port 3333
```

Endpoints:

| Route | Auth | Purpose |
|-------|------|---------|
| `POST /mcp` | yes | Streamable HTTP (MCP 2025-03-26+). `GET` opens the server event stream, `DELETE` ends the session |
| `GET /sse` + `POST /messages?sessionId=` | yes | Legacy HTTP+SSE transport for older clients |
| `GET /usage` | yes | Caller's plan, remaining quota, credit balance and lifetime counters |
| `GET /` | no | Service descriptor, endpoints, auth instructions, pricing |
| `GET /healthz` | no | Liveness probe |
| `GET /pricing` | no | Plan limits and payment options |
| `GET /payments/success`, `/payments/cancel` | no | Stripe Checkout return pages with redemption instructions |
| `POST /v1/jobs`, `GET /v1/jobs`, `GET /v1/jobs/:id`, `GET /v1/jobs/:id/results.csv`, `DELETE /v1/jobs/:id` | yes | Bulk checks over REST (when storage is available) |
| `GET /signup`, `POST /v1/keys/checkout`, `GET /keys/success` | no | Self-serve API key signup through Stripe subscriptions (when configured) |
| `POST /v1/keys/rotate` | yes | Replace the caller's self-serve key with a new one (while signup is configured) |
| `POST /v1/stripe/webhook` | Stripe signature | Keeps self-serve keys in step with their subscriptions |

Rate-limit headers `X-RateLimit-Limit`, `X-RateLimit-Http-Limit` and `X-RateLimit-Plan` are set
on every authenticated response, `X-RateLimit-Remaining` and `X-RateLimit-Reset` on each one within
the HTTP request ceiling, and a `429` from that ceiling carries `Retry-After` instead;
`X-RateLimit-Limit` is the plan's tool calls per minute and `X-RateLimit-Http-Limit` the ceiling
on HTTP requests of any kind (initialize, tools/list, ping and tool calls). Requests that end
before a principal is resolved (invalid keys or tokens, payment redemption, 402 challenge minting)
are throttled per client address (`STACKDNS_UNAUTHENTICATED_PER_MINUTE`, default 60; set
`STACKDNS_TRUST_PROXY` correctly behind a load balancer or every client shares one address). A
prepaid session that can serve the request and re-attaches a payment header the server answers
without asking Stripe or the facilitator (already redeemed, unconfirmed, expired, or still being
settled or recorded) counts against its own ceiling instead. Sessions can only be driven or ended
by the principal that initialized them. A request for
another principal's session answers 404 so a client whose identity changed simply re-initializes.
Per-address limits treat an IPv6 client's whole /64 as one address.

With `STACKDNS_REQUIRE_AUTH=false`, requests without credentials run as an anonymous principal
per client address, on the `free` plan whenever the server sells access (keys, payments or
signup) and on `local` only on a server that sells nothing. Such requests from a browser page on
an origin not listed in `STACKDNS_ALLOWED_ORIGINS` are refused with 403, so a web page cannot act
as its visitor.

### API keys

Generate keys (the raw key is shown once; the server stores only the SHA-256 hash):

```bash
npm run keys:generate -- --plan pro --label "Acme Corp"
npm run keys:generate -- --plan enterprise --count 5 --json > new-keys.json
```

The `--json` output contains the raw keys. Hand them out, then keep only `id`, `keyHash`,
`prefix`, `plan`, `label` and `active` in the keys file and delete the raw output; the plain output
prints that hashes-only block for you. A key file that still has `key` fields works, but leaves the
raw keys on the server. `.gitignore` covers `keys.json` and `new-keys.json` at the project root so
neither is committed by accident.

Load them either inline or from a file:

```bash
# small deployments
export STACKDNS_API_KEYS="sdm_live_abc...:pro:Acme Corp,sdm_live_def...:free:Trial"

# recommended: hashes only, no raw keys on the server
export STACKDNS_API_KEYS_FILE=/etc/stackdns/keys.json
```

`keys.json`:

```json
[
  { "id": "key_1f2e3d4c5b6a", "keyHash": "<sha256 hex>", "prefix": "sdm_live_abc12", "plan": "pro", "label": "Acme Corp", "active": true }
]
```

Clients send `Authorization: Bearer sdm_live_...` or `X-API-Key: sdm_live_...`. A key file
path that does not exist yet (a fresh volume, say) is logged and treated
as zero file-backed keys; a file that exists but cannot be parsed is a startup error.

### Self-serve API keys (Stripe subscriptions)

Set `STRIPE_SECRET_KEY` and a recurring Stripe Price for one or both plans
(`STRIPE_PRICE_PRO=price_...`, `STRIPE_PRICE_ENTERPRISE=price_...`) and `GET /signup` becomes a
plan page. The buyer subscribes through Stripe Checkout and lands on `/keys/success`, which issues
the key and shows it exactly once; a second visit (the Checkout Session id in the URL is a payment
reference that leaks through logs and dashboards) never shows or re-issues it. A payment that is
still clearing (bank debits) gets its key on that first visit too, inactive until Stripe confirms
the payment, so the id cannot be used by someone else to claim the key first. A subscription that
has already ended when the buyer opens the page (Stripe reports it canceled or expired, or a
subscription webhook has recorded its cancellation, expiry or deletion) answers `410` and shows no
key; so does a reload of that page. The key's plan follows the subscription's current price. Keys
are stored as SHA-256 hashes in the database next to the configured ones and work on every route.
A buyer replaces a key with `POST /v1/keys/rotate` (authenticated with the current key; available
while signup is configured, and after it is switched off the operator rotates keys), and the
account keeps its bulk checks, watches, alerts and usage across rotations.

Point a Stripe webhook at `POST /v1/stripe/webhook` with the events
`customer.subscription.created`, `customer.subscription.updated` and
`customer.subscription.deleted`, and set `STRIPE_WEBHOOK_SECRET=whsec_...`. Keys are then
suspended while a subscription is past due, unpaid or paused, restored when it recovers, moved to
the new plan when the price changes, and revoked for good when the subscription is deleted. Events
are applied once and in order, and signatures older than five minutes are refused. The webhook
stays mounted whenever `STRIPE_WEBHOOK_SECRET` is set, even after signup is switched off, so keys
already sold keep following their subscriptions. Without the webhook secret, keys keep working
after a cancellation, and the server warns about it at startup.
Signup and checkout requests share the per-address ceiling for unauthenticated traffic.

### Bulk checks over REST

The bulk-check tools are also a plain REST API for spreadsheets and scripts, with the same
billing, limits and ownership:

```bash
# CSV or plain text: the first column of each line (a header row such as "domain" or "website" is skipped)
curl -X POST "https://mcp.example.com/v1/jobs?check=email" \
  -H "Authorization: Bearer sdm_live_..." -H "Content-Type: text/csv" --data-binary @leads.csv

# or JSON
curl -X POST https://mcp.example.com/v1/jobs -H "Authorization: Bearer sdm_live_..." \
  -H "Content-Type: application/json" -d '{"check":"tech","domains":["acme.com","globex.com"]}'

curl -H "Authorization: Bearer sdm_live_..." https://mcp.example.com/v1/jobs/job_...            # status and one page (?offset, ?limit, ?status)
curl -H "Authorization: Bearer sdm_live_..." https://mcp.example.com/v1/jobs/job_.../results.csv -o results.csv
curl -X DELETE -H "Authorization: Bearer sdm_live_..." https://mcp.example.com/v1/jobs/job_...  # cancel pending items
```

`POST` answers `202` with the job and a `Location` header. The CSV export has one row per
submitted line in the original order, with the check's summary columns; cells that a spreadsheet
would run as a formula are prefixed with `'`. `GET /v1/jobs/:id` refuses an unknown `?status` and
a non-numeric `?offset` or `?limit` with `400` instead of ignoring them.

Errors from the job service, and request bodies that are not valid JSON or are too large, use the
tool error shape `{ "error": { "code", "message", "retryable", "details" } }` with a matching HTTP
status (400 invalid input, 401 anonymous caller, 402 insufficient credits, 404 unknown job or
route, 413 too many domains or a body over the limit, 429 quota or too many active jobs). A JSON
body may be 1 MiB and a CSV body 2 MiB, or more when `STACKDNS_BULK_MAX_DOMAINS` is raised (64
bytes for each of the twice-the-maximum raw entries a job accepts). Requests turned away by
authentication before the route runs (401 bad key or token, 403 browser origin, 409, 429 request
ceiling, 502, 503) use `{ "error": "<code>", "message": ... }` like every other HTTP route, and a
402 carries the payment challenge body.

### Plans and rate limits

| Plan | Tool calls / minute | Tool calls / day | Concurrent | HTTP requests / minute |
|------|--------------------:|-----------------:|-----------:|-----------------------:|
| `free` | 10 | 100 | 2 | 50 |
| `pro` | 60 | 5 000 | 8 | 300 |
| `enterprise` | 300 | 100 000 | 32 | 1 500 |
| `payg` (prepaid credits) | 60 | 1 000 000 | 8 | 300 |
| `local` (stdio, no keys) | 120 | 1 000 000 | 8 | 600 |

The daily cap of `payg` and `local` cannot be reached at their stock per-minute rates; it only
matters when an override raises `perMinute`. Override any value with `STACKDNS_RATE_LIMITS_JSON='{"free":{"perMinute":5},"pro":{"perDay":20000,"httpPerMinute":600}}'`
(`httpPerMinute` defaults to five times `perMinute`, never below 30). All four values are reported
by `GET /pricing`. Usage is tracked per principal and per tool and persisted atomically to
`STACKDNS_USAGE_FILE`; idle per-address and per-payment principals with no remaining credits are
dropped from the ledger after 90 days, API-key counters are kept forever. With
`STACKDNS_DB_FILE=none`, unfinished x402 settlements are kept in the usage file too (format version
3; older files still load), so a restart still knows a payment whose settle never answered.
Pointing the server at a database later moves them into it.

### HTTP 402 payment challenges

Enable with `STACKDNS_PAYMENTS_ENABLED=true` and one or both methods in
`STACKDNS_PAYMENT_METHODS`. With `STACKDNS_REQUIRE_AUTH=true` (the HTTP default), a request that
carries no credentials, a prepaid session that has run out of credits on a paid call or a job
submission, and a payment credential that was refused (unpaid, expired, rejected by the
facilitator) all receive the following (an invalid key or session token gets `401`, and an
unparseable payment credential gets `400`):

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="chl_...", realm="stack-and-dns-mcp", methods="stripe x402",
                  intent="charge", expires="2026-09-16T22:00:00.000Z", request="<base64url JSON>"
Content-Type: application/json

{
  "x402Version": 1,
  "error": "payment_required",
  "accepts": [ { "scheme": "exact", "network": "base", "maxAmountRequired": "500000", "asset": "0x8335...", "payTo": "0x...", ... },
               { "scheme": "stripe", "extra": { "checkoutUrl": "https://checkout.stripe.com/...", "paymentIntentId": "pi_...", "clientSecret": "..." } } ],
  "challenge": { "id": "chl_...", "methods": ["stripe", "x402"], "instructions": { ... } }
}
```

The header follows the Machine Payments Protocol `WWW-Authenticate: Payment` shape and the body
is x402-compatible, so both agent ecosystems can parse it.

**Stripe flow**

1. Set `STRIPE_SECRET_KEY`, optionally `STRIPE_PRICE_CENTS` (default 500 = $5.00),
   `STRIPE_CREDITS_PER_PURCHASE` (default 100) and `STRIPE_CURRENCY`.
2. The challenge carries a PaymentIntent `clientSecret` (for programmatic confirmation) and a
   hosted Checkout `checkoutUrl` (for a human operator).
3. After paying, the agent retries with
   `Authorization: Payment <base64url({"method":"stripe","challengeId":"chl_...","paymentIntentId":"pi_..."})>`
   (or `checkoutSessionId` from the success page).
4. The server verifies the PaymentIntent through the Stripe API (status, amount, currency,
   service metadata, not already redeemed), grants credits and answers the original request. The
   response carries `Payment-Receipt` (base64url JSON) and `X-Session-Token`.
5. Subsequent calls use `Authorization: Bearer sdm_sess....` until the credits run out, at which
   point a fresh 402 is issued. Session tokens expire 30 days after issue (an expired token gets
   `401 invalid_session_token`). Every successful payment or top-up returns a fresh token in
   `X-Session-Token` and the `Payment-Receipt`; switch to it, because an expired token can no
   longer reach the credits left on it.
6. To top up without changing identity (and therefore without losing an open MCP session), keep
   `Authorization: Bearer <existing sdm_sess token>` and add `X-PAYMENT` (or send
   `Authorization: Payment <credential>` plus `X-Session-Token: <existing token>`); the credits are
   added to that principal, the same token stays valid until its own expiry, and the response
   carries a fresh 30-day token. An invalid or expired token sent with a payment is rejected with
   `401` before anything is charged.
7. Re-presenting an already-redeemed payment credential answers `409` (never `402`) and carries the
   current payment challenge (`WWW-Authenticate` header and `accepts` body), so a client that keeps
   re-sending its last payment header learns how to buy more without auto-paying on a duplicate. A
   credential that is mid-verification in a concurrent request answers a plain
   `409 payment_redemption_in_progress` with `Retry-After: 2`. Neither is a 402, so a duplicate
   retry can never charge twice. A payment reference alone is deliberately not a credential: it
   never re-issues a session token, so keep the token from the `Payment-Receipt`. A funded prepaid
   session that also carries a stale or unredeemable payment header is served from its own balance
   (with an `X-Payment-Status` header naming the reason). This includes a payment whose settlement
   is unconfirmed (`X-Payment-Status: x402_settlement_unconfirmed`); it also is not counted against
   the per-address limit while its stored answer is used. So is an exhausted session on requests
   that cannot spend credits (reading or cancelling jobs). A session re-sending a payment header
   that is already redeemed is limited by its own plan's rate limit, not by the per-address limit
   for unauthenticated requests.
8. Redeemed payment ids are remembered for 400 days (well past card dispute windows) and a
   PaymentIntent older than that is refused with `payment_too_old`, so an id that has aged out of
   the ledger can never be presented again for fresh credits. An x402 authorization whose
   `validBefore` has passed is refused as `x402_expired` before any facilitator call for the same
   reason.

**x402 / MPP flow**

1. Set `X402_FACILITATOR_URL` (a facilitator exposing `/verify` and `/settle`), `X402_PAY_TO`
   (your wallet), and optionally `X402_NETWORK`, `X402_ASSET`, `X402_ASSET_NAME`,
   `X402_ASSET_VERSION`, `X402_PRICE_ATOMIC`, `X402_CREDITS_PER_PAYMENT`. `X402_ASSET_NAME` and
   `X402_ASSET_VERSION` are the token's EIP-712 domain, which clients sign over (`extra.name` and
   `extra.version` in every requirement; `GET /pricing` shows them as `payments.x402.assetName`
   and `payments.x402.assetVersion`), so they must equal the contract's `name()` and `version()`.
   `X402_ASSET`, `X402_ASSET_NAME` and `X402_ASSET_VERSION` each default to USDC on
   `X402_NETWORK`: on `base` (or `eip155:8453`) `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`,
   `USD Coin`, `2`; on `base-sepolia` (or `eip155:84532`)
   `0x036CbD53842c5426634e7929541eC2318f3dCF7e`, `USDC`, `2`. On any other network, startup with
   x402 enabled fails unless `X402_ASSET` and `X402_ASSET_NAME` are set (the version still defaults
   to `2`). With x402 enabled, startup also refuses the built-in USDC contract of one network on
   the other, a name or version that differs from that contract's EIP-712 domain, and an
   `X402_ASSET` that is a token other than the network's USDC without `X402_ASSET_NAME`, because
   every payment would fail; set `X402_ASSET_VERSION` too if that token's `version()` is not `2`.
   `X402_NETWORK` is matched against the built-in names case-insensitively and sent in their
   canonical spelling (`Base-Sepolia` is sent as `base-sepolia`, `EIP155:8453` as `eip155:8453`),
   because clients and facilitators compare network ids exactly; any other network id is sent as
   written, only trimmed, since CAIP-2 references can be case-sensitive.
2. The agent signs an `exact` payment for the advertised requirements and retries with the
   `X-PAYMENT: <base64 payload>` header (or `Authorization: Payment ...`).
3. The server calls the facilitator to verify and settle, records the transaction, qualified by
   the authorization's payer and nonce, to prevent replay, grants credits and returns the receipt
   and session token as above.

Set `STACKDNS_SESSION_SECRET` so session tokens survive restarts, and give every process that
shares the database the same value: a token signed by one process is otherwise rejected (`401`)
by the others, including the token a `503` or `502` hands out, which no retry re-issues. Credits
are refunded automatically when a metered call fails.

### Reconciling x402 settlements

```bash
npm run settlements -- list                      # payments that need an operator (oldest first, at most 1000)
npm run settlements -- list --all --json
npm run settlements -- resolve <paymentId> --tx <transaction hash>
npm run settlements -- resolve <paymentId> --failed
STACKDNS_SESSION_SECRET=... npm run settlements -- session <principalId>
```

The tool works on the database in `STACKDNS_DB_FILE` (or `--db <file>`) and is safe to run next to
live servers: each change is one transaction that first checks the marker is still as listed. It
does not edit markers kept in the usage file (`STACKDNS_DB_FILE=none`). From a build, run
`node dist/cli/settlements.js <command>` instead; in the Docker image, for example,
`docker exec <container> node dist/cli/settlements.js list`. Exit codes: `0` done, `1` refused or
failed, `2` bad usage. Bad usage is an unknown command or option, a flag without its value, a
missing or extra argument, `resolve` without exactly one of `--tx` and `--failed`, or a `--limit`
that is not a positive whole number, all checked before the database is opened; a marker that
needs `--nonce` and is not given a usable one exits `2` as well.

- `list` shows unconfirmed payments (`unknown`), settles whose process died (`settling (stale)`)
  and settled payments whose credits are not recorded (`settled`), oldest update first. Each row
  has the payment id, principal, credits, age, time since its last update and the transaction.
  `--all` adds live settles and leftovers of payments that are already recorded; `--json` prints
  JSON. At most 1000 rows are shown (`--limit <n>` changes that). When more remain, a notice on
  stderr says so; stdout stays the table or the JSON.
- `resolve <paymentId> --tx <hash>`: you confirmed the transfer on-chain. The payment is recorded
  under the ids a server uses, and its credits go to the principal the marker names, once, however
  often you run the command, unless another presentation of the same authorization was credited
  first (it is then recorded without credits and reported as already recorded). Unlike a server,
  `resolve` does not yield to an earlier settlement of the same authorization that is not recorded
  yet: when `list` shows two `settled` markers with the same transaction, resolve the one with the
  greater age (claimed first) first, or let a running server record them. A settled marker
  accepts only the transaction the facilitator reported, and ignores `--nonce`. Any other marker
  written by an earlier release does not record its authorization, so pass `--nonce <nonce>` too
  (the EIP-3009 nonce from the payer's `X-PAYMENT` header, or from the `AuthorizationUsed` event);
  the payment is then recorded under that nonce alone. It is not credited if a server already
  credited the same authorization with its payer, and it blocks any later credit of that
  authorization. For a newer marker, `--nonce` is optional and must match the authorization's
  nonce. A settle that is still running is refused.
- `resolve <paymentId> --failed`: you confirmed nothing moved. The marker ends and the payment id
  is recorded as redeemed, so that authorization can never settle into credits on this server
  later. A payer whose authorization is still valid can then pay again with a new authorization.
  The old authorization stays valid on-chain until its `validBefore`; EIP-3009 tokens such as USDC
  let the payer cancel an unused one with `cancelAuthorization`. Settled markers are refused,
  because money moved: use `--tx`.
- `session <principalId>` prints a prepaid session token for the principal on stdout, signed with
  `STACKDNS_SESSION_SECRET` (required: it must be the HTTP servers' secret). Use it for a payer
  whose answer was lost. The principal is the one in the payment's log line or in `list`. The
  label and balance come from the database when one is available (`--label <text>` overrides the
  label); the command also works without one.

---

## Configuration reference

Every variable is optional, and the server reads only its environment. See
[`.env.example`](.env.example) for the annotated template: copy it to `.env` and load it with
`npm run start:env` (`node --env-file=.env dist/index.js`) or `docker run --env-file .env`, or set
the variables in your process manager. With `npm run start:env`, variables already set in the
environment take precedence over the file; with `docker run --env-file`, the file overrides the
image's own settings (and `-e` flags override the file). With `docker run --env-file`, leave `STACKDNS_TRANSPORT`, `STACKDNS_USAGE_FILE` and
`STACKDNS_DB_FILE` out of the file (they are commented out in the template). The image sets `http`
and the `/data` paths, and a relative `./data` is not writable by the image's non-root user. A
value that fails validation stops startup with a message naming the variable.

Command-line flags override the matching variables: `--http` (aliases `--sse`, `--remote`),
`--stdio`, `--host <h>`, `--port <n>` and `--log-level <level>`, each value also accepted as
`--flag=value`. A missing or invalid flag value stops startup too; unrecognised arguments are
ignored.

| Variable | Default | Description |
|----------|---------|-------------|
| `STACKDNS_TRANSPORT` | `stdio` | `stdio` or `http` (`--http` / `--stdio` flags override) |
| `STACKDNS_HOST` / `STACKDNS_PORT` / `PORT` | `0.0.0.0` / `3333` | Listen address for HTTP mode. The port is taken from `--port`, then `PORT` (set by most PaaS), then `STACKDNS_PORT` |
| `STACKDNS_PUBLIC_URL` | `http://localhost:<port>` | Public base URL used in payment challenges |
| `STACKDNS_ALLOWED_HOSTS` | empty | `Host` header allowlist for DNS-rebinding protection, written as clients send the header, port included (`localhost:3333,mcp.example.com`) |
| `STACKDNS_ALLOWED_ORIGINS` | empty | CORS origins. Empty = CORS for any origin on authenticated requests; anonymous browser requests (with `STACKDNS_REQUIRE_AUTH=false`) are refused unless their origin is listed; `*` allows every origin |
| `STACKDNS_DNS_REBINDING_PROTECTION` | `false` | Enable the SDK's Host/Origin validation on the MCP endpoints (`/mcp`, `/sse`, `/messages`; not the REST routes). It checks `Host` only when `STACKDNS_ALLOWED_HOSTS` is set (startup logs a warning when protection is on without it) and compares origins exactly against `STACKDNS_ALLOWED_ORIGINS`; a `*` in that list allows every origin here too, so the Origin header is then not checked (also logged as a warning) |
| `STACKDNS_TRUST_PROXY` | `false` | Express trust-proxy value behind a reverse proxy: a hop count (`1`) or a subnet/keyword list (`loopback, 10.0.0.0/8`). `true` is mapped to `1`, never to "trust every hop" |
| `STACKDNS_SESSION_TTL_MS` | `1800000` | Idle Streamable HTTP session lifetime |
| `STACKDNS_REQUIRE_AUTH` | `true` (http) / `false` (stdio) | Reject requests without a key or payment |
| `STACKDNS_API_KEYS` / `STACKDNS_API_KEYS_FILE` | empty | Inline `key:plan:label` list or JSON key file |
| `STACKDNS_API_KEY` | empty | Key this stdio process meters tool calls against; it must match a key in `STACKDNS_API_KEYS` / `STACKDNS_API_KEYS_FILE` set in the same environment (ignored when none are set). It never connects to a hosted server. A stdio server logs a warning at startup when it is set and no keys are configured |
| `STACKDNS_SESSION_SECRET` | random per boot | HMAC secret for prepaid session tokens (at least 16 characters). Keep it fixed and the same for every process sharing the database, or tokens are rejected after a restart or by a sibling. Tokens last 30 days |
| `STACKDNS_RATE_LIMITS_JSON` | built-in | Per-plan overrides (partial objects are fine) |
| `STACKDNS_UNAUTHENTICATED_PER_MINUTE` | `60` | Per-client-address ceiling for requests that end before a principal is resolved |
| `STACKDNS_USAGE_FILE` | `./data/usage.json` | Per-principal usage counters, plus a backup mirror of balances. It is the authoritative credit ledger, redeemed-payment list and x402 settlement store only when storage is disabled or unavailable; otherwise those live in `STACKDNS_DB_FILE`, the file to persist and back up |
| `STACKDNS_DB_FILE` | `./data/stackdns.db` | SQLite database for stored scans, `domain_history`, bulk jobs, watches, the crawl list, self-serve keys and the shared credit ledger. `none` (or `off`, `false`, `0`) disables storage; an unopenable path or a Node.js release without `node:sqlite` disables it with a warning instead of failing startup. An HTTP server whose database stays locked by another process for two minutes stops instead; a stdio server waits 15 seconds and then runs without storage |
| `STACKDNS_SCAN_RETENTION_DAYS` | `365` | Stored scans, change-log entries and removed technologies older than this are deleted daily; a domain's current technologies and email posture are kept however old |
| `STACKDNS_BULK_ENABLED` | `true` | Offer the bulk-check tools and REST API (needs storage) |
| `STACKDNS_BULK_MAX_DOMAINS` / `STACKDNS_BULK_MAX_ACTIVE_JOBS` | `1000` / `3` | Distinct domains per job (up to 50000; a list may carry twice as many raw entries); unfinished jobs per caller. HTTP request bodies are limited to 1 MiB of JSON and 2 MiB of CSV, raised to 128 bytes per allowed domain when that is more (6.1 MiB at 50000), so the largest accepted list fits |
| `STACKDNS_BULK_CONCURRENCY` | `4` | Bulk items checked at once, shared by all jobs |
| `STACKDNS_JOB_RETENTION_DAYS` | `30` | Finished jobs and their results are deleted after this |
| `STACKDNS_MONITOR_ENABLED` | `true` | Offer the monitoring tools (needs storage) |
| `STACKDNS_MONITOR_INTERVAL_HOURS` / `STACKDNS_MONITOR_CONCURRENCY` | `24` / `2` | How often each watched domain is re-checked; checks run at once |
| `STACKDNS_MONITOR_CREDITS_PER_CHECK` | `1` | Charged to prepaid watchers per scheduled check (`0` makes monitoring free) |
| `STACKDNS_MONITOR_WATCH_LIMITS_JSON` | `{"free":5,"pro":100,"enterprise":2000,"payg":500,"local":1000}` | Watched domains per plan (partial objects are fine) |
| `STACKDNS_ALERT_RETENTION_DAYS` | `90` | Delivered, failed and webhook-less alerts older than this are deleted |
| `STACKDNS_WEBHOOK_ALLOW_INSECURE` | `false` | Permit `http://` alert webhooks (development only; private addresses follow `STACKDNS_ALLOW_PRIVATE_TARGETS`) |
| `STACKDNS_CRAWL_SEED_FILE` | empty | Domain list (text or CSV, first column) crawled for the reverse lookup; enables `find_domains_using` and `list_technologies` |
| `STACKDNS_CRAWL_RATE_PER_MINUTE` / `STACKDNS_CRAWL_CONCURRENCY` | `20` / `2` | Homepages fetched per minute across all domains; fetches at once |
| `STACKDNS_CRAWL_REFRESH_DAYS` | `30` | How often each crawl-list domain is re-visited (failures retry sooner, backing off from one hour) |
| `STACKDNS_CRAWL_MAX_TARGETS` | `100000` | At most this many distinct valid domains (up to 5000000) are taken from the seed file, in file order; blank, comment, header, invalid and duplicate lines (a leading `www.` ignored) do not count, and the rest of the file is ignored |
| `STRIPE_PRICE_PRO` / `STRIPE_PRICE_ENTERPRISE` | empty | Recurring Stripe Price ids sold on `/signup`; with `STRIPE_SECRET_KEY` they enable self-serve keys |
| `STRIPE_WEBHOOK_SECRET` | empty | Signing secret of the `/v1/stripe/webhook` endpoint (`whsec_...`) |
| `STACKDNS_PAYMENTS_ENABLED` / `STACKDNS_PAYMENT_METHODS` | `false` / `stripe` | Enable 402 challenges; `stripe`, `x402` or both, comma-separated, in any case (any other value stops startup) |
| `STACKDNS_PAYMENT_CHALLENGE_TTL_MS` | `900000` | Challenge validity |
| `STRIPE_SECRET_KEY`, `STRIPE_PRICE_CENTS`, `STRIPE_CURRENCY`, `STRIPE_CREDITS_PER_PURCHASE`, `STRIPE_SUCCESS_URL`, `STRIPE_CANCEL_URL`, `STRIPE_API_BASE` | see `.env.example` | Stripe settings |
| `X402_FACILITATOR_URL`, `X402_PAY_TO`, `X402_NETWORK`, `X402_ASSET`, `X402_ASSET_NAME`, `X402_ASSET_VERSION`, `X402_PRICE_ATOMIC`, `X402_CREDITS_PER_PAYMENT` | see `.env.example` | x402 settings. `X402_ASSET`, `X402_ASSET_NAME` and `X402_ASSET_VERSION` default to USDC on `X402_NETWORK` (`base`: `0x8335...2913`, `USD Coin`, `2`; `base-sepolia`: `0x036C...CF7e`, `USDC`, `2`). With x402 enabled, other networks need `X402_ASSET` and `X402_ASSET_NAME`, and another token on `base` or `base-sepolia` needs `X402_ASSET_NAME`. Built-in network names match in any case and are sent in lowercase |
| `STACKDNS_FETCH_TIMEOUT_MS` | `3000` | Per-attempt homepage fetch deadline, 500-30000; the insecure-TLS retry and the `http://` fallback end by twice this |
| `STACKDNS_DNS_TIMEOUT_MS` / `STACKDNS_TLS_TIMEOUT_MS` | `3000` | DNS timeout per try (2 tries per resolver, each attempt capped at twice the value plus 250 ms; a failed query may be retried once on the other resolvers, so one query can take about 12.5 s at the default) and TLS handshake timeout |
| `STACKDNS_TOOL_TIMEOUT_MS` | `20000` | Hard ceiling for a whole tool call |
| `STACKDNS_MAX_BODY_BYTES` | `1500000` | HTML body cap |
| `STACKDNS_DNS_SERVERS` | system | Explicit resolvers, comma-separated: `ip`, `ipv4:port`, `[ipv6]:port` or `[ipv4]:port`, port 1-65535 (the fallback list takes the same forms; anything else stops startup) |
| `STACKDNS_DNS_FALLBACK_SERVERS` | `1.1.1.1,8.8.8.8,9.9.9.9` | Retried per query when the primary fails; preferred for 5 minutes only after the primary proves unreachable (connection errors, or hard timeouts across 3 distinct zones). Set to `none` to disable third-party DNS egress, which split-horizon deployments should do because public resolvers answer NXDOMAIN for internal zones |
| `STACKDNS_DNS_CACHE_TTL_MS` | `30000` | How long a successful DNS answer (including NXDOMAIN) is reused for identical queries; `0` disables the cache. Errors are never cached |
| `STACKDNS_USER_AGENT` | `Mozilla/5.0 (compatible; StackAndDnsBot/1.0; +...)` | Request User-Agent |
| `STACKDNS_ALLOW_PRIVATE_TARGETS` | `false` | Permit private / reserved targets (development only) |
| `STACKDNS_DKIM_SELECTORS` | empty | Extra selectors probed on every call |
| `STACKDNS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`, `silent` (`--log-level` overrides) |

---

## Defensive design

- **Strict input validation.** Zod schemas gate every argument; the domain parser accepts URLs,
  emails and IDN names but rejects IP literals, single labels, malformed labels and reserved TLDs.
- **SSRF protection.** Every outbound socket (HTTP fetch and TLS probe) resolves through a
  guarded `lookup` that refuses loopback, RFC 1918, CGNAT, link-local, cloud-metadata, multicast,
  reserved, ULA, IPv4-mapped and NAT64-embedded private addresses at connect time, which also
  closes the DNS-rebinding window.
- **Hard deadlines everywhere.** Per-attempt fetch deadline (default 3 s; the TLS and `http://`
  fallbacks end by twice that), per-hop redirect budget
  (max 5 hops, http/https only), TLS handshake timeout, c-ares timeout plus a hard Promise race
  on every DNS query, and a whole-call ceiling in the meter.
- **Body caps and charset-aware decoding.** Streams are cut at `STACKDNS_MAX_BODY_BYTES`; the
  result is flagged `truncated`.
- **Graceful degradation.** TLS validation failures trigger an insecure retry (flagged), an
  unreachable HTTPS origin triggers an HTTP fallback (flagged), WAF challenge pages are detected
  and reported as `blocked`, and an unreachable homepage still yields TLS and DNS data.
- **Resolver fallback.** When the host resolver refuses raw UDP (common with VPN clients and
  container stubs), queries are retried on the public resolvers and preferred there for a bounded
  window; the first successful primary answer ends the window early.
- **DNS answer cache.** Successful answers (including NXDOMAIN/NODATA) are reused for 30 seconds
  and identical in-flight queries are coalesced, so the existence probe, the MX and SPF
  evaluations and both halves of `comprehensive_audit` ask each question of the resolver once.
  Errors are never cached.
- **Cancellation.** A tool call that times out or is cancelled by the client aborts its in-flight
  fetch, TLS probe and policy download and stops fanning out further DNS probes, so abandoned work
  does not keep consuming the concurrency budget.
- **No crashes.** Tool exceptions become structured `isError` results, credits are refunded on
  failure, and `uncaughtException` / `unhandledRejection` are logged rather than fatal.
- **Secrets hygiene.** API keys are stored hashed and compared in constant time; session tokens
  are HMAC-signed; logger redacts fields that look like secrets.

---

## Scoring model

**Email deliverability (0-100):** MX 20, SPF 22, DKIM 20, DMARC 28, MTA-STS 5, TLS-RPT 3, BIMI 2.
`+all`, permerrors (multiple records: 3 of 22 SPF points; more than 10 lookups, more than 2 void
lookups or a circular include: at most 6 of 22), SPF syntax errors (at most 8 of 22), weak or
revoked DKIM keys, `p=none` and partial `pct` all reduce points; disposable domains are capped at
10; NXDOMAIN is 0. An MTA-STS DNS record whose policy file cannot be fetched or is not a valid
policy (no `version: STSv1`) earns 0 of 5; a DMARC lookup that fails scores as absent but is
reported as unconfirmed (`DMARC_DNS_ERROR` plus a medium `DMARC_MISSING`). A subdomain whose own
`_dmarc` lookup fails while the organizational record answers scores its unknown policy like
`p=none` (10 of 28); the stored score keeps the subdomain's last known DMARC points instead. Once
exchanges that never resolve are accepted as unresolvable, the stored score takes their MX points
away as it would for exchanges that do not exist.

**Security posture (0-100):** security-header score x 0.65 (HTTPS 15, HSTS 15, CSP 15,
clickjacking 10, X-Content-Type-Options 10, Referrer-Policy 8, Permissions-Policy 7, COOP 4,
CORP 3, version disclosure 5, cookie flags 8) plus TLS 35 (valid chain, hostname and dates;
deductions for imminent expiry; 8 points for a reachable but invalid certificate). HSTS earns
nothing on a page served over plaintext HTTP, where browsers must ignore it, and a present but
empty, zero or unparseable HSTS header scores 3 with an `HSTS_INVALID` finding. Referrer-Policy is
judged by its last recognised token: the leaky values (`no-referrer-when-downgrade`,
`unsafe-url`) and unrecognised values score 3 with a `REFERRER_POLICY_WEAK` finding.

**Infrastructure maturity (0-100):** presence of edge protection 15, analytics 15, tag
management 10, go-to-market stack 15, modern framework 10, recognized platform 10, consent
management 8, observability 7, customer engagement 5, experimentation 5. Blocked fetches are
reported as a lower bound.

**Overall:** email 40 % + security 35 % + infrastructure 25 %. Grades: A >= 90, B >= 80,
C >= 70, D >= 60, otherwise F.

---

## Signature database

[`src/signatures/signatures.json`](src/signatures/signatures.json) holds 450+ entries validated
at startup by [`src/signatures/schema.ts`](src/signatures/schema.ts). Each entry:

```json
{
  "id": "klaviyo",
  "name": "Klaviyo",
  "category": "email-marketing",
  "website": "https://www.klaviyo.com",
  "confidence": 100,
  "html": ["static\\.klaviyo\\.com", "_learnq"],
  "scripts": ["klaviyo\\.js"],
  "headers": { "x-powered-by": "^Klaviyo" },
  "cookies": ["__kla_id"],
  "meta": { "generator": "^Klaviyo ?([\\d.]+)?\\;version:\\1" },
  "implies": ["shopify"],
  "excludes": []
}
```

- Patterns are case-insensitive regular expressions; a trailing `\;version:\N` captures a
  version from group N (Wappalyzer convention).
- `headers` values are regexes; an empty string means "header present".
- `implies` adds transitive detections (e.g. WooCommerce implies WordPress) at reduced confidence.
- Invalid patterns are logged and skipped so one bad entry never disables detection.
- `npm test` asserts that every pattern compiles, ids are unique and categories exist.

---

## Deployment

### Docker

```bash
docker build -t stack-and-dns-mcp .
openssl rand -hex 32 > stackdns.secret   # once; keep it outside the repository (*.secret is git-ignored)
docker run -p 3333:3333 -v stackdns-data:/data \
  -e STACKDNS_PUBLIC_URL=https://mcp.example.com \
  -e STACKDNS_API_KEYS_FILE=/data/keys.json \
  -e STACKDNS_SESSION_SECRET="$(cat stackdns.secret)" \
  stack-and-dns-mcp
```

The session secret must stay the same across container re-creation and upgrades, or outstanding
session tokens, and the prepaid credits reachable only through them, stop working. Passing it
through `--env-file` works as well; keep the template's transport and data-path lines commented
out (see [Configuration reference](#configuration-reference)).

The image runs as a non-root user, exposes `/healthz` for orchestrators and keeps usage and the
SQLite database (`STACKDNS_DB_FILE=/data/stackdns.db`) on the `/data` volume. Without a named
volume or bind mount for `/data`, the data (stored scans, change history, prepaid balances) lives
in an anonymous volume tied to that one container. It survives a restart, but a re-created
container (an upgrade, a new `docker run`) starts empty, and `--rm` deletes it. The healthcheck
probes `/healthz` on the port from `PORT` or `STACKDNS_PORT` (default 3333) and passes without
probing when `STACKDNS_TRANSPORT=stdio`, which has no HTTP listener. A transport or port given
only as a command-line flag (`--stdio`, `--port`) is invisible to it, so set the variables
instead, or run with `--no-healthcheck`.

### Any Node host (Fly.io, Render, Railway, ECS, a VM)

Set `STACKDNS_TRANSPORT=http`, `PORT`, `STACKDNS_PUBLIC_URL`, a fixed `STACKDNS_SESSION_SECRET`
(the same for every process), `STACKDNS_TRUST_PROXY=true` when behind a load balancer, and mount
persistent storage for `STACKDNS_USAGE_FILE` and `STACKDNS_DB_FILE` (an ephemeral disk silently
resets stored scans, change history and balances on every deploy). Start with
`node dist/index.js --http`. Streamable HTTP sessions and rate-limit windows are held per
process, so run a single replica (or pin clients to one instance with sticky sessions and accept
per-instance quotas). Overlapping processes that share the database file are safe:

- Prepaid balances and redeemed payment ids live in the database, so a charge in one process and
  a refund in another land on the same balance, and a payment is redeemed exactly once. A usage
  file from before this is imported once.
- A lease in the database elects a single worker, so during a rolling deploy, or with several stdio
  servers started by one client, bulk items, monitor checks and crawls run once.
- Every bulk item write is fenced to the worker that claimed it, so a worker that lost the lease
  can never overwrite its successor's results.
- Each scheduled monitor check is claimed in a transaction that re-checks it is still due, so
  overlapping rounds from two processes run and charge it once.
- A process that finds the database locked at startup (a sibling's migration, say) waits for up
  to two minutes, then exits rather than run on a private ledger beside the shared one. A stdio
  server, which sells nothing, waits up to 15 seconds to open the database and again to attach
  the shared credit ledger, and otherwise runs without storage, so MCP clients do not time out its
  `initialize`. An HTTP server waits up to 15 seconds for that first attach before it exits.
- Every process must share one `STACKDNS_SESSION_SECRET`; otherwise a prepaid session token issued
  by one process is rejected (`401`) by the others.
- x402 settlements in progress are recorded in the database before the facilitator is asked to
  settle, so a retry that reaches a sibling process, or arrives after a restart, never gets a new
  payment demand for money that may already have moved.
- Each settled x402 payment is recorded under its transaction qualified by its authorization
  (`x402_<tx>:<payer>.<nonce>`; the payer is the authorization's `from`, or the payer the
  facilitator's `/verify` reports when `from` is left out, given as a 20-byte hex address or as a
  CAIP-10 account id such as `eip155:8453:0x...`). A facilitator that batches several payments into
  one transaction therefore credits each of them once, even when two payers reuse a nonce, while one
  authorization presented twice (with or without `from`) is still credited once. If both
  presentations settle while the first one's credits are still being recorded (after a database
  error, or while another process holds the write lock), the one that settled first is still the
  one credited. Within one process this always holds; across processes it holds once the first
  one's settlement is marked settled in the database. The later one is answered
  `409 payment_already_redeemed` and credited nothing. If the database refused that mark too (as
  it does while the lock is held), a sibling process cannot see the first settlement, and
  whichever presentation is recorded first is credited. `npm run settlements -- resolve` does not
  apply this rule (see [Reconciling x402 settlements](#reconciling-x402-settlements)). If no usable
  payer is known for an authorization sent without `from` (the facilitator reports none, or
  reports it in any other form), it is recorded under its nonce alone (`x402_<tx>:<nonce>`). That
  record blocks the payer-qualified one, and any payer-qualified record of the same transaction
  and nonce blocks it, whichever of the two presentations arrives first. Records written by
  earlier releases (`x402_<tx>`) still block. So does a record whose payer part is not a 20-byte
  address, such as a hashed CAIP-10 account id that an earlier release wrote (or that a server or
  `npm run settlements` writes when it finishes a marker such a release left): it counts as a
  record without a known payer, so it blocks the same authorization presented with `from`, and
  with it another payer's authorization that reuses its nonce in the same batched transaction,
  since it may be the same authorization.
- The monitor's entitlement pass (pausing, re-planning, resuming and retiring self-serve watches)
  takes the write lock only when an account's watches need a change. When another process holds
  that lock, the rest of the pass waits for the next round instead of failing the round.

---

## Publishing to MCP marketplaces

1. **npm**: bump `version` in `package.json` and both version fields in `server.json` (the
   top-level `version` and `packages[0].version`), then
   `npm publish --access public`. `prepublishOnly` rebuilds and runs the tests. The `mcpName`
   field ties the npm package to the registry entry below.
2. **Official MCP Registry** (registry.modelcontextprotocol.io): edit
   [`server.json`](server.json) so `name` uses your GitHub namespace
   (`io.github.<your-user>/stack-and-dns-mcp`), add your hosted `remotes[].url`, then
   `mcp-publisher login github`, `mcp-publisher validate` and `mcp-publisher publish`. The
   registry verifies ownership of the npm package through `mcpName` (keep it equal to `name`),
   and its schema limits `description` to 100 characters.
3. **Cursor directory / Claude connectors / Glama / PulseMCP / mcp.so**: submit the GitHub URL
   and the hosted `/mcp` endpoint; each directory reads `server.json` or the README config blocks.
4. **Docker MCP Catalog**: submit the image built from the Dockerfile with the `--http` entrypoint.

---

## Development and testing

```bash
npm run dev          # stdio with tsx (no build)
npm run dev:http     # HTTP on :3333
npm run typecheck
npm test             # node:test suites, offline (analyzers, scoring, auth, payments and ledger, bulk jobs, monitor, crawler, scan store)
npm run format       # Prettier (.prettierrc.json); npm run format:check only reports
npm run smoke -- example.com

# real MCP client round trip (initialize, tools/list, tools/call) over each transport, after npm run build
node scripts/e2e-client.mjs stdio example.com
SDM_KEY=sdm_live_... node scripts/e2e-client.mjs http example.com   # against localhost:3333 (override with SDM_URL)
```

`npm test`, and therefore `npm publish` (`prepublishOnly`), needs Node.js 22.13+: the suites use
`node:sqlite`, and on Windows, where npm runs scripts through `cmd.exe`, only Node's own `--test`
expands `test/*.test.ts`. The suite never connects off the machine: DNS is scripted, servers
listen on 127.0.0.1, and the HTTPS end-to-end tests make their self-signed loopback certificate in
process (`test/fixtures/loopback-cert.ts`), so they need no `openssl` binary and none are skipped.

Project layout:

```text
src/
  index.ts                 entrypoint, transport selection, storage and ledger attach, process guards
  config.ts                Zod-validated env/CLI configuration and plan limits
  server.ts                McpServer factory and instructions
  schemas.ts               tool input/output Zod contracts
  services.ts              storage-backed services and background workers (bulk, monitor, crawler, maintenance)
  logger.ts                JSON-lines stderr logger
  tools/                   inspect_tech_stack, verify_email_infrastructure, comprehensive_audit,
                           domain_history, bulk checks, monitoring, reverse lookup
  signatures/              signatures.json (450+), schema, compile + match engine
  middleware/              auth (API keys, session tokens), payments (Stripe, x402), rate limiter,
                           per-address throttle, usage ledger, tool-call meter
  transports/              stdio, Express (Streamable HTTP + SSE) and the /v1/jobs REST API (jobsApi.ts)
  store/                   SQLite schema and migrations (v1-v10), stored scans, bulk jobs, monitor,
                           crawler, reverse index, credit ledger and x402 settlement markers,
                           self-serve keys, worker lease
  billing/                 self-serve key signup and the Stripe API client
  cli/generate-key.ts      API key generator (npm run keys:generate)
  cli/settlements.ts       operator reconciliation of x402 settlements (npm run settlements)
  lib/                     domain parsing, DNS client with fallback, HTTP fetcher, TLS inspector,
                           SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT/BIMI analyzers, security headers,
                           WAF detection, scoring, SSRF guards, robots.txt, domain lists, webhooks
  types/                   ambient type declarations
  data/disposable-domains.json
test/                      node:test suites (test/fixtures/ holds shared helpers)
scripts/smoke.ts           run tools directly
scripts/e2e-client.mjs     real MCP client round trip over stdio or HTTP
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `NETWORK_ERROR ... ECONNREFUSED` on every call | The host resolver refuses UDP; the built-in fallback to 1.1.1.1/8.8.8.8 handles it automatically. Set `STACKDNS_DNS_SERVERS` to force resolvers. |
| `blocked.blocked = true` for a site | The site's WAF challenged the request. Detection is partial; the result still reports the WAF vendor, headers, TLS and DNS. |
| `DKIM not found` for a domain that signs mail | The provider uses a non-standard selector. Pass it via `dkimSelectors` or set `STACKDNS_DKIM_SELECTORS`. |
| 401 on every HTTP request | `STACKDNS_REQUIRE_AUTH` is true but no keys, payment methods or self-serve signup are configured (the server warns at startup). Add keys or set it to `false`. |
| Session tokens rejected after a restart, or by another instance | Set a fixed `STACKDNS_SESSION_SECRET`, the same for every process. |
| Prepaid token rejected after about a month | Session tokens last 30 days; use the token from your most recent payment or top-up. |
| `502 x402_settlement_unconfirmed` | The facilitator did not confirm the settle; do not pay again. Retry the same header later, or have the operator reconcile it with `npm run settlements` (see "Reconciling x402 settlements"). |
| Startup fails with a message naming a variable or flag | Its value is not accepted (for example an unknown payment method, a resolver that is not an IP address, `--port abc`, or with x402 enabled an `X402_ASSET` or `X402_ASSET_NAME` that does not fit `X402_NETWORK`, or a token other than the network's USDC without `X402_ASSET_NAME`); fix or unset it. |
| Claude Desktop does not show the tools | Use absolute paths in `args` and for `STACKDNS_USAGE_FILE` / `STACKDNS_DB_FILE`, run `npm run build` first, and check the logs at `%APPDATA%\Claude\logs`. |

---

MIT License. Copyright (c) 2026 Mewnah.
